// SPDX-License-Identifier: GPL-2.0-only
/*
 * kavach.bpf.c — unity build of every Kavach eBPF program into one object, so all programs
 * share one instance of each map. Each program keeps its own source file (see the diagrams).
 */
#include "xdp_filter.c"
#include "lsm_egress.c"
#include "tc_flow.c"

char LICENSE[] SEC("license") = "GPL";
