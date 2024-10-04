#!/bin/bash

TIME=gtime
which $TIME

RUSTFLAGS=-Ctarget-cpu=native $TIME -f "Peak memory: %M kb CPU usage: %P" cargo run --release --package mimc_pallas_hash --bin mimc_pallas_hash