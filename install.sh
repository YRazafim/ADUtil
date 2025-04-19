#!/bin/sh

sudo apt install -y libkrb5-dev krb5-user pipx freerdp2-x11 xvfb faketime
/usr/bin/pipx install . --force
