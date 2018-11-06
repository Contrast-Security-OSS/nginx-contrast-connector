#!/bin/bash

set -e

package=$(ls ./pkgs | awk '!/dbg/ && /bionic/' | head -n 1)
apt install ./pkgs/${package} -y