#!/bin/bash

#ssh -p 8022 -i bastian_id.rsa -t bastian@localhost "sudo cat /proc/modules | awk '{if(\$1 == \"$1\") print \$6}'"
ssh -p 8022 -i bastian_id.rsa -t bastian@localhost "sudo cat /sys/module/$1/sections/.text"
