/*Error Messages*/
#define BIG_SET_ERR_MSG                                                        \
    "ERROR: Number of set index bits needs to be less than 64.\n"
#define NEG_SET_ERR_MSG                                                        \
    "ERROR: Number of set index bits needs to be non-negative.\n"
#define BIG_BLK_ERR_MSG                                                        \
    "ERROR: Number of block bits needs to be less than 64.\n"
#define NEG_BLK_ERR_MSG                                                        \
    "ERROR: Number of block bits needs to be non-negative.\n"
#define NEG_LIN_ERR_MSG "ERROR: Number of lines per set needs to be positive.\n"
#define BIG_SET_BLK_ERR_MSG                                                    \
    "ERROR: The total number of set index bits and block bits needs to be "    \
    "less than or equal to 64.\n"
#define INC_ARG_ERR_MSG                                                        \
    "ERROR: Number of set index bits, block bits, lines or trace file was "    \
    "not provided.\n"
#define FIL_ERR_MSG "ERROR: Invalid tracing file provided.\n"


/*Structs*/

/*individual cache line*/
typedef struct CacheLine {
    int dirty_bit;
    unsigned long tag_val;
    struct CacheLine *next_line;
    struct CacheLine *prev_line;
} cache_line;

/*individual cache set*/
typedef struct CacheSet {
    unsigned long empty_lines;
    int empty_flag;
    cache_line *first_line;
    cache_line *last_line;
} cache_set;


/*Function Prototypes*/

/** @brief Processing the operation of a line in the trace file and update on
 * the cache reading statistics.*/
void process_op(char op, unsigned long tag, cache_set *cur_cache_block,
                cache_op_tally *op_tally);

/** @brief To go over a trace file and simulate the cache operations with it.*/
int process_trace_file(arg_cache_spec *cache_spec, cache_set *main_cache,
                       cache_op_tally *op_tally);

/** @brief Create the mask for slicing specific bits.*/
unsigned long valid_bit_mask(unsigned long bound_left,
                             unsigned long bound_right);

/** @brief moving a line to the front of a cache set.*/
void move_line_forward(cache_set *cur_cache_block, 
                       cache_line *new_head_line);


/**
 * @brief Processing the operation of a line in the trace file and update on the
 * cache reading statistics
 *
 * @param op The operation that will happen
 * @param tag The tag parameter of the operation
 * @param cur_cache_block The cache set the operation will happen in
 * @param op_tally The overall statistics on the cache reading
 *
 */
void process_op(char op, unsigned long tag, cache_set *cur_cache_block,
                cache_op_tally *op_tally) {
    /*first line to put in the current cache set*/
    if (cur_cache_block->empty_flag) {
        op_tally_change(OP_TAL_INC_MIS, op_tally); // cold miss
        init_cache_block(cur_cache_block, tag, op);
        if (op == S_ASCII)
            op_tally_change(OP_TAL_INC_DBC, op_tally); // dirty if it's store op
        return;
    } else {
        cache_line *matching_line =
            search_for_line(cur_cache_block->first_line, tag);
        /*found some line so that we put the found line to the most recent use*/
        if (matching_line != NULL) {
            op_tally_change(OP_TAL_INC_HIT, op_tally); // found so it is a hit
            if (op == S_ASCII && matching_line->dirty_bit == 0) {
                matching_line->dirty_bit = 1;
                op_tally_change(
                    OP_TAL_INC_DBC,
                    op_tally); // operation store makes the block dirty
            }
            move_line_forward(cur_cache_block, matching_line);
            /*otherwise if not found we would need to create a new line and add
             * it to the front*/
        } else {
            op_tally_change(OP_TAL_INC_MIS, op_tally); // not found so miss
            insert_line_head(cur_cache_block, tag, op, op_tally);
            if (cur_cache_block->empty_lines ==
                0) // evict when the cache set is full
                remove_line_tail(cur_cache_block, op_tally);
            else
                cur_cache_block->empty_lines--;
        }
    }
}

/**
 * @brief To go over a trace file and simulate the cache operations with it
 *
 * @param cache_spec The spec of the cache we will be working on
 * @param main_cache The overall cache that we will be operating on
 * @param op_tally The overall statistics on the cache reading
 *
 * @return The result of the reading with 1 indicating the reading has failed,
 * i.e. bad trace file and 0 indicating success
 */
int process_trace_file(arg_cache_spec *cache_spec, cache_set *main_cache,
                       cache_op_tally *op_tally) {

    /*masks for extracting tag and set*/
    unsigned long tag_mask =
        valid_bit_mask(MAX_BITS, cache_spec->block_bits + cache_spec->set_bits);
    unsigned long set_mask = valid_bit_mask(
        cache_spec->block_bits + cache_spec->set_bits, cache_spec->block_bits);
    unsigned long set_index_clean_mask =
        valid_bit_mask(cache_spec->set_bits, 0);

    FILE *tfp = fopen(cache_spec->trace_file, "rt");
    if (!tfp) {
        printf(FIL_ERR_MSG);
        return 1;
    }

    char linebuf[MAX_LINE_CHAR + 1]; // To allow reading in one more character
                                     // to test if the input is too long
    int parse_error = 0;

    while (fgets(linebuf, MAX_LINE_CHAR + 1, tfp)) {

        if (strlen(linebuf) > MAX_LINE_CHAR - 1) {
            parse_error = 1;
            break;
        }

        char op;
        unsigned long addr;
        unsigned long size_byte;

        char *line_token;
        int token_count;
        line_token = strtok(
            linebuf, LINE_DELIM); // splitting up lines with space and comma
        token_count = 0;

        while (line_token != NULL) {
            token_count++;

            if (token_count >
                LINE_TOK_NUM) { // too many elements in trace file, invalid
                parse_error = 1;
                break;
            }

            if (token_count == 1) { // should get the op of L or S
                if (strlen(line_token) != 1) {
                    parse_error = 1;
                    break;
                }
                if ((char)(line_token[0]) != L_ASCII &&
                    (char)(line_token[0]) != S_ASCII) {
                    parse_error = 1;
                    break;
                }
                op = (char)(line_token[0]);
            }

            if (token_count == 2) { // should get the address of 16 byte
                if (strlen(line_token) > MAX_ADDR_BIT) {
                    parse_error = 1;
                    break;
                }
                addr = strtoul(line_token, NULL, BASE_16);
            }

            if (token_count == 3) { // should get the size , a singular digit
                if (strlen(line_token) != 2) {
                    parse_error = 1;
                    break;
                }
                if ((char)(line_token[0]) < ZERO_ASCII &&
                    (char)(line_token[0]) > NINE_ASCII) { // not a number
                    parse_error = 1;
                    break;
                }
                if ((char)(line_token[1]) !=
                    NEW_LINE_CHAR) { // should immediately end the line after
                                     // reading this
                    parse_error = 1;
                    break;
                }
                size_byte = strtoul(line_token, NULL, BASE_10);
            }

            line_token = strtok(NULL, LINE_DELIM);
        }

        if (token_count != LINE_TOK_NUM) // too many arguments
            parse_error = 1;
        if (parse_error == 1)
            break;

        unsigned long tag_addr;
        unsigned long set_index_addr;

        /* getting the tag and set of the operation to work on*/

        tag_addr = tag_mask & addr;
        set_index_addr = ((set_mask & addr) >> cache_spec->block_bits) &
                         set_index_clean_mask;

        process_op(op, tag_addr, &main_cache[set_index_addr], op_tally);
    }

    fclose(tfp);

    return parse_error;
}

/**
 * @brief Create the mask for slicing specific bits
 *
 * @param bound_left the left margin,
 * @param bound_right the right margin,
 *
 * @return The bit-wise mask of the bits that will be valid
 */
unsigned long valid_bit_mask(unsigned long bound_left,
                             unsigned long bound_right) {
    unsigned long left_mask;
    unsigned long right_mask;
    if (bound_right >= 64 || bound_left <= bound_right)
        return 0;
    else
        right_mask =
            ((1L) << bound_right) - 1; // up until the bits on the right to omit
    if (bound_left >= 64)
        left_mask = (unsigned long)(-1);
    else
        left_mask =
            ((1L) << bound_left) - 1; // up until the bits on the left to omit
    return left_mask ^ right_mask;
}

/**
 * @brief moving a line to the front of a cache set
 *
 * @param cur_cache_block The cache set that the moving will happen
 * @param new_head_line The line that is to become the new line head
 *
 */
void move_line_forward(cache_set *cur_cache_block, cache_line *new_head_line) {
    if (cur_cache_block->first_line !=
        new_head_line) { // no neede to move if the line is already a first line
        if (new_head_line->next_line != NULL)
            (new_head_line->next_line)->prev_line = new_head_line->prev_line;
        if (new_head_line->prev_line != NULL)
            (new_head_line->prev_line)->next_line = new_head_line->next_line;
        new_head_line->next_line = cur_cache_block->first_line;
        if (cur_cache_block->last_line ==
            new_head_line) // if the new head was the last line, new tail is the
                           // line to the front of it
            cur_cache_block->last_line = new_head_line->prev_line;
        new_head_line->prev_line = NULL;
        (cur_cache_block->first_line)->prev_line = new_head_line;
        cur_cache_block->first_line = new_head_line; // setting new head
    }
}
