#!/bin/bash

USERNAME="testuser"
PASSWORD="password"

# Create the user if not exists
if ! id "$USERNAME" &>/dev/null; then
    useradd -m "$USERNAME"
    echo "[+] User $USERNAME created"
    
    # Set password
    echo "$USERNAME:$PASSWORD" | chpasswd
    echo "[+] Password set for $USERNAME"
else
    echo "[*] User $USERNAME already exists"
fi

# Copy .bashrc file if exists
if [ -f "./tools/testuser/files/.bashrc" ]; then
    cp ./tools/testuser/files/.bashrc /home/$USERNAME/
    chown $USERNAME:$USERNAME /home/$USERNAME/.bashrc
    echo "[+] .bashrc copied to $USERNAME home directory"
fi

# Copy mailbox file if exists
if [ -f "./tools/testuser/files/mailbox" ]; then
    cp ./tools/testuser/files/mailbox /var/mail/$USERNAME
    chown $USERNAME:mail /var/mail/$USERNAME
    chmod 660 /var/mail/$USERNAME
    echo "[+] Mailbox restored and permissions set"
fi

echo "[✓] Setup of $USERNAME is complete"
