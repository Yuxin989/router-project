cc = gcc
EXEC = demo
OBJ = main.o get_interface.o fun.o
LIBS = -lmysqlclient -lpcap -lpthread -lnet
# CFLAGS

$(EXEC):$(OBJ)
	$(cc) $^ $(LIBS) -o $@
%.o:%.c
	$(cc) -c $< -o $@

clean:
	rm -rf $(EXEC) $(OBJ)