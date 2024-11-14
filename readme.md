# Packet sniffer

Packet sniffer is a simple networking utility that allows the user to capture and display packets that are transmitted over a network. Specificaly this utility works with the Transport layer's protocols TCP and UDP.

## Installation

After cloning the repository, you can install the utility by running the following command:

```bash
make build
```
This creates an executable file called `main.out` in the root directory of the repository.

Repository also contains a additional make command to create a debugable executable file:

```bash
make debug
```

Resulting executable file is called `debug.out`, and can be used to debug the application using `gdb`.

## Usage

Utility featueres a simple command line interface that allows the user to specify the network interface to listen on and the output stream to write the captured packets to. The following command line arguments are supported:

```bash
-h --help: Display help message
-t TCP or -t UDP: Specify the protocol to capture
-o STREAM or -o FILE filename: Specify the output stream to write the captured packets to
```
The application by default runs indefinitely until the user stops it by pressing `Ctrl+C`.

## Example

```bash
sudo ./main.out -t TCP -o FILE output.txt
```

This command will start the packet sniffer and capture only TCP packets. The captured packets will be written to the file `output.txt`.

## Technologies

- C programming language
- `netinet`
- `arpa`
- Make build system
- GDB debugger
- Valgrind memory leak detector