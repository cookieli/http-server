CC=gcc
CFLAGS= -I.
_OBJ =  y.tab.o lex.yy.o parse.o logging.o common.o handle_client.o response.o liso_server.o 
FLAGS = -g -Wall
PARSE_DIR = parser
LOG_DIR  = log
OBJ_DIR = obj
UTILITIES_DIR = utilities
HANDLER_DIR = handler

DEPS = $(LOG_DIR)/logging.h $(PARSE_DIR)/y.tab.h $(PARSE_DIR)/parse.h $(UTILITIES_DIR)/common.h $(HANDLER_DIR)/handle_client.h $(HANDLER_DIR)/response.h lisod.h


OBJ = $(patsubst %,$(OBJ_DIR)/%, $(_OBJ))

lisod:$(OBJ) 
	$(CC) -o $@ $^ -lssl

$(OBJ_DIR)/y.tab.o: $(PARSE_DIR)/y.tab.c $(DEPS)
	$(CC) $(FLAGS) -c $< -o $@

$(OBJ_DIR)/lex.yy.o: $(PARSE_DIR)/lex.yy.c $(DEPS)
	$(CC) $(FLAGS) -c $< -o $@

$(OBJ_DIR)/parse.o: $(PARSE_DIR)/parse.c $(DEPS)
	$(CC) $(FLAGS) -c $< -o $@

$(OBJ_DIR)/logging.o: $(LOG_DIR)/logging.c $(DEPS)
	$(CC) $(FLAGS) -c $< -o $@

$(OBJ_DIR)/common.o: $(UTILITIES_DIR)/common.c $(UTILITIES_DIR)/common.h -lssl
	$(CC) $(FLAGS) -c $< -o $@
$(OBJ_DIR)/handle_client.o: $(HANDLER_DIR)/handle_client.c $(DEPS)
	$(CC) $(FLAGS) -c $< -o $@
$(OBJ_DIR)/response.o: $(HANDLER_DIR)/response.c $(HANDLER_DIR)/response.h
	$(CC) $(FLAGS) -c $< -o $@
$(OBJ_DIR)/liso_server.o: lisod.c $(DEPS)
	$(CC) $(FLAGS) -c $< -o $@

$(PARSE_DIR)/lex.yy.c: $(PARSE_DIR)/lexer.l
	flex -o $@ $^

$(PARSE_DIR)/y.tab.c: $(PARSE_DIR)/parser.y
	yacc -d $^
	mv y.tab.* $(PARSE_DIR)/

.PHONY: clean
clean:
	rm $(PARSE_DIR)/y.tab.* $(PARSE_DIR)/lex.yy.c
	rm -f $(OBJ_DIR)/*.o
	rm lisod
	rm -f /WWW
	rm -f message/*.log
	rm -f message/*.lock


