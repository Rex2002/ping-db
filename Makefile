pDB: pDB.c
	$(CC) pDB.c -o pDB -Wall -Wextra -pedantic -std=c99
piDB: piDB.c
	$(CC) -g piDB.c -o piDB -Wall -Wextra -pedantic -std=c99