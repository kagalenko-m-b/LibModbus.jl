# LibModbus.jl

[![Build Status](https://github.com/kagalenko-m-b/LibModbus.jl/workflows/CI/badge.svg)](https://github.com/kagalenko-m-b/LibModbus.jl/actions)
[![Codecov](https://codecov.io/gh/kagalenko-m-b/LibModbus.jl/branch/master/graph/badge.svg)](https://codecov.io/gh/kagalenko-m-b/LibModbus.jl)

Julia wrapper for [Libmodbus](http://libmodbus.org/) library

## Installation

Within julia, execute
```julia
using Pkg; Pkg.add("LibModbus")
```

## Usage example

```julia
julia> ctx = RtuContext(raw"\\.\COM10", 9600, :even, 8, 1)
RtuContext(serial_port \\.\COM10, baud 9600, parity even, data_bits 8, stop_bits 1)

julia> connect(ctx)
0

julia> ctx.slave_address=1
1

julia> res=read_input_registers(ctx, 0, 15)
read input registers:
15-element Vector{UInt16}:
 0xd9f6
 0x00fc
 0xded1
 0x806a
 0xbe81
 0xcf72
 0xbfae
 0x7487
 0xb42d
 0xe370
 0xc9d8
 0x67a9
 0xeb4f
 0xc288
 0xd686

julia> disconnect(ctx)
```

If you reassigned `ctx` while the serial port is still connected,
call `GC.gc()` to trigger the finalizer on `ModbusContext`.

See the test directory for more usage examples .
