## Usage

run `make piDB && ./piDB` in `sudo`-mode.

- write to the database: `write {your text}` \
the text is automatically distributed to more than one packet if required (only 34 data bytes per packet) \
- to read from the database: `read {id}` \
If the packet does not exist according to the index-packets, the user will be informed. 
If the packet exists according to the index-packets, but was lost due to other reasons, the program will search forever :(
- to delete from the database: `delete {id}` \
drops the packet if it is encountered and deletes the reference from the according index packet.
One needs to be careful when deleting index-packets, since deleting them does not result in deleting the referenced data-packets as well

To display the log, open a different terminal and execute `tail -f log.txt`

## Issues

Many, including:

1. some how packets seem to duplicate / be sent very often in a row, this extremely slows down reading -> only occurs when using targets other than localhost
2. updating packets theoretically works but is not callable from stdin yet
3. not enough slow but reliable servers
