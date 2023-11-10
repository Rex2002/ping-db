## Usage

write to the database: `write {your text}`
the text is automatically distributed to more than one packet if required (only 33 data bytes per packet)
to read from the database: `read {id}`
currently only present id's can be found, otherwise the program will search forever.

To display the log, call a different terminal and execute `tail -f log.txt`

## Issues

Many, including:

1. some how packets seem to duplicate / be sent very often in a row, this extremely slows down reading  
2. cannot delete packets
3. unknown which packets actually exist
4. cannot update packets
5. not enough slow but reliable servers  
