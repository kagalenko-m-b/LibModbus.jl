module LibModbus

using LibModbus_jll

export ModbusMapping, TcpContext, RtuContext
export MbExcpt, MODBUS_ERROR_RECOVERY_NONE, MODBUS_ERROR_RECOVERY_LINK
export MODBUS_ERROR_RECOVERY_PROTOCOL
export modbus_context_valid
export modbus_set_slave, modbus_get_slave, modbus_set_socket!, modbus_get_socket
export modbus_get_response_timeout, modbus_set_response_timeout, modbus_get_byte_timeout
export modbus_set_byte_timeout, modbus_set_error_recovery
export modbus_get_header_length, modbus_connect
export modbus_close, modbus_flush, modbus_free!, modbus_set_debug
export modbus_read_bits, modbus_read_input_bits, modbus_read_registers
export modbus_read_input_registers, modbus_write_bit, modbus_write_register
export modbus_write_bits, modbus_write_registers, modbus_mask_write_register
export modbus_write_and_read_registers, modbus_send_raw_request
export modbus_reply_exception, modbus_report_slave_id
export modbus_mapping_new_start_address, modbus_mapping_new
export modbus_mapping_free!, modbus_receive, modbus_reply
export modbus_tcp_listen, modbus_tcp_accept, tcp_close
export modbus_rtu_set_serial_mode, modbus_rtu_get_serial_mode
export modbus_rtu_set_rts, modbus_get_rts, modbus_set_rts_delay
export modbus_get_rts_delay

@enum Modbus_error_recovery_mode::Cint begin
    MODBUS_ERROR_RECOVERY_NONE = 0
    MODBUS_ERROR_RECOVERY_LINK = 1<<1
    MODBUS_ERROR_RECOVERY_PROTOCOL = 1<<2
end

@enum MbExcpt::UInt8 begin
    MODBUS_EXCEPTION_ILLEGAL_FUNCTION = 0x01
    MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS
    MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE
    MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE
    MODBUS_EXCEPTION_ACKNOWLEDGE
    MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY
    MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE
    MODBUS_EXCEPTION_MEMORY_PARITY
    MODBUS_EXCEPTION_NOT_DEFINED
    MODBUS_EXCEPTION_GATEWAY_PATH
    MODBUS_EXCEPTION_GATEWAY_TARGET
    MODBUS_EXCEPTION_MAX
end



mutable struct ModbusMapping
    nb_bits::Cint
    start_bits::Cint
    nb_input_bits::Cint
    start_input_bits::Cint
    nb_input_registers::Cint
    start_input_registers::Cint
    nb_registers::Cint
    start_registers::Cint
    tab_bits::Ptr{UInt8}
    tab_input_bits::Ptr{UInt8}
    tab_input_registers::Ptr{UInt16}
    tab_registers::Ptr{UInt16}
end

abstract type ModbusContext end
mutable struct Modbus_t end

@doc raw"""
    TcpContext(ip_address, port=502)

Create libmodbus context for TCP

# Arguments
- `ip_address::String`: the IP address of the server to which the client wants to establish
a connection. A NULL value can be used to listen any addresses in server mode.
- `port::Integer`: the TCP port to use. It's convenient to use a port number greater than
or equal to 1024 because it's not necessary to have administrator privileges.
"""
struct TcpContext <: ModbusContext
    ip_address::String
    port::Cint
    _ctx_ptr::Ref{Ptr{Modbus_t}}
    function TcpContext(ip_address::String, port::Integer)
        ctx_ptr = ccall((:modbus_new_tcp, libmodbus), Ptr{Modbus_t}, (Cstring, Cint),
                        ip_address, port)
        if ctx_ptr == C_NULL
            _strerror(-1, "TcpContext()")
        end
        ctx = new(ip_address, port, ctx_ptr)
    end
end
const MODBUS_TCP_MAX_ADU_LENGTH = 260

modbus_context_valid(::Nothing) = false
modbus_context_valid(ctx::ModbusContext) = ctx._ctx_ptr[] != C_NULL

function Base.show(io::IO, ctx::TcpContext)
    color = modbus_context_valid(ctx) ? :green : :red
    str = modbus_context_valid(ctx) ? "ip $(ctx.ip_address), port $(ctx.port)" : "NULL"
    printstyled(io, "TcpContext($(str))"; color)
end

@doc raw"""
    RtuContext(serial_port, baud, parity, data_bits, stop_bits)

Create libmodbus context for RTU

# Arguments
- `serial_port::String`: specifies the name of the serial port handled by the OS

Example:  "/dev/ttyS0" or "/dev/ttyUSB0". On Windows, it's necessary to prepend COM name
with "\.\" for COM number greater than 9, eg. "\\.\COM10".
See http://msdn.microsoft.com/en-us/library/aa365247(v=vs.85).aspx for details
- `baud::Integer`: baud rate of the communication, eg. 9600, 19200, 57600, 115200, etc.
- `parity::Symbol`: can have one of the following values:
    :N for none
    :E for even
    :O for odd
- `data_bits::Integer`: the number of bits of data, the allowed values are 5, 6, 7 and 8.
- `stop_bits::Integer`: the bits of stop, the allowed values are 1 and 2.

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
struct RtuContext <: ModbusContext
    serial_port::String
    baud::Cint
    parity::Symbol
    data_bits::Cint
    stop_bits::Cint
    _ctx_ptr::Ref{Ptr{Modbus_t}}
    function RtuContext(
        serial_port::String,
        baud::Integer,
        parity::Symbol,
        data_bits::Integer,
        stop_bits::Integer
        )
        if parity === :none
            prt = 'N'
        elseif parity === :even
            prt = 'E'
        elseif parity === :odd
            prt = 'O'
        else
            error("unknown parity value specified")
        end
        5 <= data_bits <= 8 || error("the data_bits value of $(data_bits) is not allowed")
        1 <= stop_bits <= 2 || error("the stop_bits value of $(stop_bits) is not allowed")
        ctx_ptr = ccall((:modbus_new_rtu, libmodbus), Ptr{Modbus_t},
                        (Cstring, Cint, Cchar, Cint, Cint),
                        serial_port, baud, prt, data_bits, stop_bits)
        if ctx_ptr == C_NULL
            _strerror(-1, "RtuContext()")
        end
        ctx = new(serial_port, baud, parity, data_bits, stop_bits, ctx_ptr)
        return ctx
    end
end

function Base.show(io::IO, ctx::RtuContext)
    color = modbus_context_valid(ctx) ? :green : :red
    str =  (modbus_context_valid(ctx) ?
        "RtuContext(serial_port $(ctx.serial_port), baud $(ctx.baud), parity $(ctx.parity), "*
        "data_bits $(ctx.data_bits), stop_bits $(ctx.stop_bits))" :
        "NULL" )
    printstyled(io, str; color)
end

# Common for RTU and TCP contexts
"""
    modbus_set_slave(ctx::ModbusContext, slave::Integer) -> Int32

Set the slave number in the libmodbus context. The behavior depends of network
and the role of the device:

RTU

Define the slave ID of the remote device to talk in master mode or set the internal
slave ID in slave mode. According to the protocol, a Modbus device must only accept
message holding its slave number or the special broadcast number.

TCP

The slave number is only required in TCP if the message must reach a device
on a serial network. 

The broadcast address is MODBUS_BROADCAST_ADDRESS. This special value must be used
when you want all Modbus devices of the network receive the request.

# Arguments
- `ctx::ModbusContext`: libmodbus context
-`slave::Integer`: slave number

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_set_slave(ctx::ModbusContext, slave::Integer)
    ret = ccall((:modbus_set_slave, libmodbus), Cint, (Ptr{Cvoid}, Cint),
                ctx._ctx_ptr[], slave)
    _strerror(ret, "modbus_set_slave()")

    return ret
end

"""
    modbus_get_slave(ctx::ModbusContext) -> Int32

Get the slave number in the libmodbus context.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: slave number if successful, otherwise return -1 and set errno
"""
function modbus_get_slave(ctx::ModbusContext)
    ret = ccall((:modbus_get_slave, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_slave()")

    return ret
end

"""
    modbus_set_socket!(ctx::ModbusContext, s::Integer) -> Int32

Set the socket or file descriptor in the libmodbus context. This function is useful
for managing multiple client connections to the same server.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `s::Integer`: socket or file descriptor 

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_set_socket!(ctx::ModbusContext, s::Integer)
    ret = ccall((:modbus_set_socket, libmodbus), Cint, (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], s)
    _strerror(ret, "modbus_set_socket!()")

    return ret
end

"""
    modbus_get_socket(ctx::ModbusContext) -> Int32

Get the current socket of the context 

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: current socket or file descriptor of the context if successful,
    otherwise return -1 and set errno
"""
function modbus_get_socket(ctx::ModbusContext)
    ret = ccall((:modbus_get_socket, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_socket()")

    return ret
end


"""
    modbus_get_response_timeout(ctx::ModbusContext) -> Int32,Int,Int

Get timeout interval used to wait for a response

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
- `to_sec::Int`: seconds of the response timeout
- `to_usec`: microseconds of the response timeout
"""
function modbus_get_response_timeout(ctx::ModbusContext)
    to_sec = Ref{UInt32}()
    to_usec = Ref{UInt32}()
    ret = ccall((:modbus_get_response_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt32}, Ref{UInt32}),
                ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_get_response_timeout()")

    return ret,Int(to_sec[]),Int(to_usec[])
end

"""
    modbus_set_response_timeout(ctx::ModbusContext, to_sec::Integer, to_usec::Integer) 
                                                                                    -> Int32

Set the timeout interval used to wait for a response. When a byte timeout is set,
if elapsed time for the first byte of response is longer than the given timeout,
an ETIMEDOUT error will be raised by the function waiting for a response.
When byte timeout is disabled, the full confirmation response must be received before
expiration of the response timeout.

The value of to_usec argument must be in the range 0 to 999999.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `to_sec::Integer`: seconds of the response timeout
- `to_usec::Integer`: microseconds part of the response timeout

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_set_response_timeout(ctx::ModbusContext,  to_sec::Integer, to_usec::Integer)
    ret = ccall((:modbus_set_response_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, UInt32, UInt32), ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_set_response_timeout()")

    return ret
end

"""
    modbus_get_byte_timeout(ctx::ModbusContext) -> Int32,Int,Int

Timeout interval between two consecutive bytes of the same message 

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
- `to_sec::Int`: seconds of the byte timeout
- `to_usec`: microseconds of the byte timeout
"""
function modbus_get_byte_timeout(ctx::ModbusContext)
    to_sec = Ref{UInt32}(0)
    to_usec = Ref{UInt32}(0)
    ret = ccall((:modbus_get_byte_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt32}, Ref{UInt32}), ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_get_byte_timeout()")

    return ret,Int(to_sec[]),Int(to_usec[])
end

"""
    modbus_set_byte_timeout(ctx::ModbusContext, to_sec::Integer, to_usec::Integer) -> Int32

Set the timeout interval between two consecutive bytes of the same message. The timeout
is an upper bound on the amount of time elapsed before select() returns, if
the time elapsed is longer than the defined timeout, an ETIMEDOUT error will be raised 
by the function waiting for a response.

The value of to_usec argument must be in the range 0 to 999999.

If both to_sec and to_usec are zero, this timeout will not be used at all.
In this case, modbus_set_response_timeout() governs the entire handling of the response,
the full confirmation response must be received before expiration of the response timeout. 
When a byte timeout is set, the response timeout is only used to wait for
until the first byte of the response.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `to_sec::Int`: seconds of the byte timeout
- `to_usec`: microseconds of the byte timeout

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_set_byte_timeout(ctx::ModbusContext, to_sec::Integer, to_usec::Integer)
    ret = ccall((:modbus_set_byte_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, UInt32, UInt32), ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_set_byte_timeout()")

    return ret
end

# function modbus_get_indication_timeout(ctx::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

#   # int
# end

# function modbus_set_indication_timeout(ctx::ModbusContext, uint32_t to_sec, uint32_t to_usec)

#   # int
# end
"""
    modbus_set_error_recovery(ctx::ModbusContext, err_rec::Integer) -> Int32

Set the error recovery mode to apply when the connection fails or the byte received is not
expected. The argument error_recovery may be bitwise-or'ed with zero or more
of the following constants.

By default there is no error recovery (MODBUS_ERROR_RECOVERY_NONE) so the application
is responsible for controlling the error values returned by libmodbus functions
and for handling them if necessary.

When MODBUS_ERROR_RECOVERY_LINK is set, the library will attempt an reconnection
after a delay defined by response timeout of the libmodbus context. This mode will try
an infinite close/connect loop until success on send call and will just try one time
to re-establish the connection on select/read calls (if the connection was down,
the values to read are certainly not available any more after reconnection,
except for slave/server). This mode will also run flush requests after a delay
based on the current response timeout in some situations (eg. timeout of select call).
The reconnection attempt can hang for several seconds if the network to the remote target
unit is down.

When MODBUS_ERROR_RECOVERY_PROTOCOL is set, a sleep and flush sequence will be used
to clean up the ongoing communication, this can occurs when the message length is invalid,
the TID is wrong or the received function code is not the expected one.
The response timeout delay will be used to sleep.

The modes are mask values and so they are complementary.

It's not recommended to enable error recovery for slave/server.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `to_sec::Int`: seconds of the byte timeout
- `to_usec`: microseconds of the byte timeout

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function  modbus_set_error_recovery(ctx::ModbusContext, err_rec::Integer)
    ret = ccall((:modbus_set_error_recovery, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], Cint(err_rec))
    _strerror(ret, "modbus_set_error_recovery()")

    return ret
end

"""
    modbus_get_header_length(ctx::ModbusContext) -> Int32

Retrieve the current header length from the backend. 

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: the header length as an integer value, -1 in case of error.
"""
function modbus_get_header_length(ctx::ModbusContext)
    ret = ccall((:modbus_get_header_length, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_header_length()")

    return ret
end

"""
    modbus_connect(ctx::ModbusContext) -> Int32

Establish a connection to a Modbus server, a network or a bus using the context information
of libmodbus context given in argument.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_connect(ctx::ModbusContext)
    ret = ccall((:modbus_connect, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_connect()")

    return ret
end

"""
    modbus_close(ctx::ModbusContext)

Close the connection established with the backend set in the Modbus context.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
nothing
"""
function modbus_close(ctx::ModbusContext)
    ccall((:modbus_close, libmodbus), Cvoid, (Ptr{Cvoid},), ctx._ctx_ptr[])
end

"""
    modbus_free!(ctx::ModbusContext)

Free an allocated ModbusContext structure.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
nothing
"""
function modbus_free!(ctx::ModbusContext)
    ccall((:modbus_free, libmodbus), Cvoid, (Ptr{Cvoid},), ctx._ctx_ptr[])
    ctx._ctx_ptr[] = C_NULL

    return nothing
end

"""
    modbus_flush(ctx::ModbusContext) -> Int32

Discard data received but not read to the socket or file descriptor associated
to the context.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 or the number of flushed bytes
    if successful.
"""
function modbus_flush(ctx::ModbusContext)
    ret = ccall((:modbus_flush, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_flush()")

    return ret
end

"""
    modbus_set_debug(ctx::ModbusContext, flag::Bool) -> Int32

Set the debug flag of the context. By default, the boolean flag is set to false.
When the flag value is set to true, display verbose messages.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `flag::Bool`: display debug information if true

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_set_debug(ctx::ModbusContext, flag::Bool)
    ret = ccall((:modbus_set_debug, libmodbus), Cint, (Ptr{Cvoid},Cint),
                ctx._ctx_ptr[], flag)
    _strerror(ret, "modbus_set_debug()")

    return ret
end

function _strerror(return_code::Integer, message::AbstractString)
    err_no::Cint = Libc.errno()
    if return_code < 0
        str = ccall((:modbus_strerror,libmodbus), Cstring, (Cint,), err_no)
        @warn "$(message): "*unsafe_string(str)
    end

    return nothing
end

"""
    modbus_read_bits(ctx::ModbusContext, addr::Integer, nb::Integer) -> Int32,BitVector

Read the status of the nb bits (coils) at the address addr of the remote device and
return a bit vector of the results.

The function uses the Modbus function code 0x01 (read coil status).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address to begin reading at
- `nb::Integer`: number of coils to read

# Returns
- `rc::Int`: the return code is -1 in case of error, number of read bits if successful.
- `bv::BitVector`: bitarray of the coils' state
"""
function modbus_read_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}),
                ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_bits()")
    bv = ret > 0 ? BitVector(dest[1:ret]) : BitVector[]

    return ret,bv
end

"""
    modbus_read_input_bits(ctx::ModbusContext, addr::Integer, nb::Integer) -> Int32,BitVector

Read the nb input bits beginning at the address addr of the remote device and
return a bit vector of the results.

The function uses the Modbus function code 0x02 (read input status).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address to begin reading at
- `nb::Integer`: number of coils to read

# Returns
- `rc::Int`: the return code is -1 in case of error, number of read bits if successful.
- `bv::BitVector`: bitarray of the coils' state.
"""
function modbus_read_input_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_input_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}),
                ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_input_bits()")
    bv = ret > 0 ? BitVector(dest[1:ret]) : BitVector[]
    
    return ret,bv
end

"""
    modbus_read_registers(ctx::ModbusContext, addr::Integer, nb::Integer) -> Int32,Vector

Read the content of the nb holding registers beginning at the address addr of
the remote device. The result of reading is stored in dest array as word values (16 bits).

The function uses the Modbus function code 0x03 (read holding registers).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address to begin reading at
- `nb::Integer`: number of registers to read

# Returns
- `rc::Int`: the return code is -1 in case of error, number of read registers if successful.
- `v::Vector{UInt16}`: contents of the holding registers
"""
function modbus_read_registers(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_registers()")
    ret <= 0 || ret == nb || @warn "read $(ret) registers instead of $(nb)"

    return ret,dest[1:ret]
end

"""
    modbus_read_input_registers(ctx::ModbusContext, addr::Integer, nb::Integer) -> Int32

Read the content of the nb input registers to address addr of the remote device.
The result of the reading is stored in dest array as word values (16 bits).

The function uses the Modbus function code 0x04 (read input registers). The holding
registers and input registers have different historical meaning, but nowadays
it's more common to use holding registers only.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address to begin reading at
- `nb::Integer`: number of registers to read

# Returns
- `rc::Int`: the return code is -1 in case of error, number of read registers if successful.
- `v::Vector{UInt16}`: contents of the input registers
"""
function modbus_read_input_registers(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_input_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_input_registers()")
    ret <= 0 || ret == nb || @warn "read $(ret) registers instead of $(nb)"

    return ret,dest[1:ret]
end

"""
    modbus_write_bit(ctx::ModbusContext, coil_addr::Integer, status::Bool) -> Int32

Wwrite the status at the address addr of the remote device.

The function uses the Modbus function code 0x05 (force single coil).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `coil_addr::Integer`: address of the coil
- `status`: status to write

# Returns
- `rc::Int`: the return code is -1 in case of error, 1 if successful.
"""
function modbus_write_bit(ctx::ModbusContext, coil_addr::Integer, status)
    ret = ccall((:modbus_write_bit, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint), ctx._ctx_ptr[], coil_addr, status)
    _strerror(ret, "modbus_write_bit()")

    return ret
end

"""
    modbus_write_register(ctx::ModbusContext, reg_addr::Integer, value::Integer) -> Int32

Write the value to the  holding register at the address addr of the remote device.

The function uses the Modbus function code 0x06 (preset single register).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address of the holding register
- `value::Integer`: value to write to the register

# Returns
- `rc::Int`: the return code is -1 in case of error, 1 if successful.
"""
function modbus_write_register(ctx::ModbusContext, reg_addr::Integer, value::Integer)
    ret = ccall((:modbus_write_register, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16), ctx._ctx_ptr[], reg_addr, value)
    _strerror(ret, "modbus_write_register()")

    return ret
end

"""
     modbus_write_bits(ctx::ModbusContext, addr::Integer, data::Vector) -> Int32

Write the status of the nb bits (coils) of data beginning at the address addr
of the remote device. The src array must contain bytes or logical values.

The function uses the Modbus function code 0x0F (force multiple coils).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address of beginning coil
- `data::Integer`: values to write to the coils

# Returns
- `rc::Int`: the return code is -1 in case of error, number of written bits if successful.
"""
function modbus_write_bits(
    ctx::ModbusContext, addr::Integer, data::Vector{T}
    ) where T<:Union{Bool,UInt8}
    nb = length(data)
    ret = ccall((:modbus_write_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, data)
    _strerror(ret, "modbus_write_bits()")
    ret <= 0 || ret == nb || @warn "wrote $(ret) bits instead of $(nb)"

    return ret
end

"""
    modbus_write_registers(ctx::ModbusContext, addr::Integer, data::Vector) -> Int32

Write the content of array data[] beginning at the address addr of the remote device.

The function uses the Modbus function code 0x10 (preset multiple registers).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address of the first register to write
- `data::Integer`: values to write to the registers

# Returns
- `rc::Int`: the return is -1 in case of error, number of written registers if successful.
"""
function modbus_write_registers(
    ctx::ModbusContext, addr::Integer, data::AbstractVector{UInt16}
    )
    nb = length(data)
    ret = ccall((:modbus_write_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), ctx._ctx_ptr[], addr, nb, data)
    _strerror(ret, "modbus_write_registers()")
    ret <= 0 || ret == nb || @warn "wrote $(ret) registers instead of $(nb)"

    return ret
end
"""
    modbus_mask_write_register(args...) -> Int32

 Modify the value of the holding register at the address addr of the remote device
using the algorithm:

new value = (current value AND and_mask) OR (or_mask AND (NOT 'and'))

The function uses the Modbus function code 0x16 (mask single register).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address of the register to modify
- `and_mask::UInt16`: AND mask 
- `or_mask::UInt16`: OR mask

# Returns
- `rc::Int`: the return is -1 in case of error, 1 if successful. 
"""
function modbus_mask_write_register(ctx::ModbusContext,
                                    addr::Integer,
                                    and_mask::UInt16,
                                    or_mask::UInt16)
    ret = ccall((:modbus_mask_write_register, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16, UInt16),
                ctx._ctx_ptr[], addr, and_mask, or_mask)
    _strerror(ret, "modbus_mask_write_register()")

    return ret
end

"""
    modbus_write_and_read_registers(args...) -> Int32,Vector

Write the content of the array write_data[] to the holding registers beginning
at the adddress write_addr, then read the content of the read_nb holding registers
beginning at the address read_addr. 

The function uses the Modbus function code 0x17 (write/read registers).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `write_addr::Integer`: address of the holding register to begin writing at
- `write_data::AbstractVector{UInt16}`: data to write to the device
- `read_addr::Integer`: address to begin reading holding registers from 
- `read_nb::UInt16`: number of holding registers to read

# Returns
- `rc::Int`: the return code is -1 in case of error, number of read registers if successful. 
"""
function modbus_write_and_read_registers(
    ctx::ModbusContext,
    write_addr::Integer,
    write_data::AbstractVector{UInt16},
    read_addr::Integer,
    read_nb::Integer
    )
    write_nb = length(write_data)
    dest = Vector{UInt16}(undef, read_nb)
    ret = ccall((:modbus_write_and_read_registers, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}, Cint, Cint, Ref{UInt16}),
                ctx._ctx_ptr[], write_addr, write_nb, write_data, read_addr,
                read_nb, dest)
    _strerror(ret, "modbus_write_and_read_registers()")
    ret <= 0 || ret == read_nb || @warn "read $(ret) registers instead of $(read_nb)"

    return ret,dest[1:ret]
end

"""
     modbus_send_raw_request(ctx::ModbusContext, raw_req::AbstractVector{UInt8}) -> Int32

Send a request via the socket of the context ctx. This function must be used
for debugging purposes because you have to take care to make a valid request by hand.
The function only adds to the message the header or CRC of the selected backend,
so raw_req must start and contain at least a slave/unit identifier and a function code.
This function can be used to send request not handled by the library.

The public header of libmodbus provides a list of supported Modbus functions codes,
prefixed by MODBUS_FC_ (eg. MODBUS_FC_READ_HOLDING_REGISTERS), to help build of raw requests.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `raw_req::Vector{UInt8}`: byte sequence to send

# Returns
- `rc::Int`: the return code is -1 in case of error, the full message length,
     counting the extra data relating to the backend, if successful.
"""
function modbus_send_raw_request(ctx::ModbusContext, raw_req::AbstractVector{UInt8})
    nb = length(raw_req) - 1
    ret = ccall((:modbus_send_raw_request, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cint),
                ctx._ctx_ptr[], raw_req, nb)
    _strerror(ret, "modbus_send_raw_request()")

    return ret
end

"""
    modbus_reply_exception(args...) -> Int32

Send an exception reponsebased on the exception_code in argument.

The libmodbus provides the following exception codes:
    MODBUS_EXCEPTION_ILLEGAL_FUNCTION (1)
    MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS (2)
    MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE (3)
    MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE (4)
    MODBUS_EXCEPTION_ACKNOWLEDGE (5)
    MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY (6)
    MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE (7)
    MODBUS_EXCEPTION_MEMORY_PARITY (8)
    MODBUS_EXCEPTION_NOT_DEFINED (9)
    MODBUS_EXCEPTION_GATEWAY_PATH (10)
    MODBUS_EXCEPTION_GATEWAY_TARGET (11)
The initial request req is required to build a valid response.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `req::Vector{UInt8}`: request to respond to
- ` exception_code::MbExcpt`: exception code to send 

# Returns
- `rc::Int`: the return code is -1 in case of error, length of the response sent if
    successful.
"""
function modbus_reply_exception(
    ctx::ModbusContext, req::AbstractVector{UInt8}, exception_code::MbExcpt
    )
    ret = ccall((:modbus_reply_exception, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cuint),
                ctx._ctx_ptr[], req, exception_code)

    _strerror(ret, "modbus_reply_exception()")

    return ret
end

"""
    modbus_report_slave_id(ctx::ModbusContext, max_dest::Integer) -> Int32,Vector

Send a request to the controller to obtain a description of the controller.
The response stored in dest contains:
- the slave ID, this unique ID is in reality not unique at all so it's not possible to depend on it to know how the information are packed in the response.
- the run indicator status (0x00 = OFF, 0xFF = ON)
- additional data specific to each controller. For example, libmodbus returns the version of the library as a string.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `max_dest::Integer`: number of bytes sent from the device to return to caller

# Returns
- `rc::Int`: the return code is -1 in case of error, number of read data bytes 
    if successful. If the output was truncated due to the max_dest limit then
    the return value is the number of bytes which would have been written to dest
    if enough space had been available. Thus, a return value greater than max_dest
    means that the response data was truncated.
- `vec::Vector{UInt8}`: response from the controller 
"""
function modbus_report_slave_id(ctx::ModbusContext, max_dest::Integer)
    dest = zeros(UInt8, max_dest)
    ret = ccall((:modbus_report_slave_id, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Ref{UInt8}), ctx._ctx_ptr[], max_dest, dest)
    _strerror(ret, "modbus_report_slave_id()")

    return ret,dest
end

"""
    modbus_mapping_new_start_address(args...) -> Ptr{ModbusMapping}

Allocate four arrays to store bits, input bits, registers and inputs registers. 
The pointers are stored in modbus_mapping_t structure. All values of the arrays
are initialized to zero.

The different starting adresses make it possible to place the mapping at any address
in each address space. This way, you can give access to values stored at high adresses
without allocating memory from the address zero, for eg. to make available registers
from 10000 to 10009, you can use:

   mb_mapping = modbus_mapping_new_start_address(0, 0, 0, 0, 10000, 10, 0, 0);

With this code, only 10 registers (uint16_t) are allocated.

If it isn't necessary to allocate an array for a specific type of data, you can pass the zero value in argument, the associated pointer will be NULL.

This function may be used to handle requests in a Modbus server/slave.

# Arguments
- `start_bits::Integer`: beginning address for coils
- `nb_bits::Integer`: number of coils
- `start_input_bits::Integer`: beginning address for input bit registers
- `nb_input_bits::Integer`: number of input bit registers
- `start_registers::Integer`: beginning address for holding registers
- `nb_registers::Integer`: number of holding registers
- `start_input_registers::Integer`: beginning address for input registers
- `nb_input_registers::Integer`: number of input registers

# Returns pointer to ModbusMapping structure if successful, C_NULL pointer otherwise
"""
function modbus_mapping_new_start_address(
    start_bits::Integer,
    nb_bits::Integer,
    start_input_bits::Integer,
    nb_input_bits::Integer,
    start_registers::Integer,
    nb_registers::Integer,
    start_input_registers::Integer,
    nb_input_registers::Integer
    )
    mbm_ptr = ccall((:modbus_mapping_new_start_address, libmodbus), Ptr{ModbusMapping},
                    (Cint, Cint, Cint, Cint, Cint, Cint, Cint, Cint),
                    start_bits, nb_bits, start_input_bits, nb_input_bits,
                    start_registers, nb_registers, start_input_registers,nb_input_registers)
    _strerror(-Int(mbm_ptr == C_NULL), "modbus_mapping_new_start_address()")

    return mbm_ptr
end

"""
     modbus_mapping_new_start_address(args...) -> Ptr{ModbusMapping}

Allocate four arrays to store bits, input bits, registers and inputs registers. 
The pointers are stored in modbus_mapping_t structure. All values of the arrays
are initialized to zero.

This function is equivalent to a call of the modbus_mapping_new_start_address()
function with all start addresses to 0.

If it isn't necessary to allocate an array for a specific type of data, you can pass
the zero value in argument, the associated pointer will be NULL.

# Arguments
- `nb_bits::Integer`: number of coils
- `nb_input_bits::Integer`: number of input bit registers
- `nb_registers::Integer`: number of holding registers
- `nb_input_registers::Integer`: number of input registers

# Returns 
-`ptr`: pointer to ModbusMapping structure if successful, C_NULL pointer otherwise
"""
function modbus_mapping_new(
    nb_bits::Integer,
    nb_input_bits::Integer,
    nb_registers::Integer,
    nb_input_registers::Integer
    )
    mbm_ptr = ccall((:modbus_mapping_new, libmodbus), Ptr{ModbusMapping},
                    (Cint, Cint, Cint, Cint),
                    nb_bits, nb_input_bits, nb_registers, nb_input_registers)
    _strerror(-Int(mpm_ptr == C_NULL), "modbus_mapping_new()")

    return mbm_ptr
end

"""
    modbus_mapping_free!(mbm_ptr::Ptr{ModbusMapping})

Free the four arrays of ModbusMappping structure pointed to by mbm_ptr and then
the structure itself.

"""
function modbus_mapping_free!(mbm_ptr::Ptr{ModbusMapping})
    ccall((:modbus_mapping_free, libmodbus), Cvoid,
          (Ptr{ModbusMapping},), mbm_ptr)
end

"""
    modbus_receive(ctx::TcpContext) -> rc,Vector

Receive an indication request from the socket of the context ctx. This function is used
by Modbus slave/server to receive and analyze indication request sent by the masters/clients.

If you need to use another socket or file descriptor then the one defined in the context ctx,
see the function modbus_set_socket().

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: the return code is -1 in case of error, the request length if successful.
- `req::Vector{UInt8}`: the indication request received.
"""
function modbus_receive(ctx::TcpContext)
    req = Vector{UInt8}(undef, MODBUS_TCP_MAX_ADU_LENGTH)
    ret = ccall((:modbus_receive, libmodbus), Cint, (Ptr{Cvoid}, Ref{UInt8}),
                ctx._ctx_ptr[], req)
    _strerror(ret, "modbus_receive()")

    return ret,req[1:ret]
end

"""
    modbus_reply(args...) -> Int32

Send a response to received request. The request req given in argument is analyzed,
a response is then built and sent by using the information of the modbus context ctx.

If the request indicates to read or write a value, the operation will done in the modbus
mapping mb_mapping according to the type of the manipulated data.

If an error occurs, an exception response will be sent.

This function is designed for Modbus server.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `req::AbstractVector{UInt8}`: request received by server
- `mbm_ptr::Ptr{ModbusMapping}`: pointer to the structure describing the registers

# Returns
- `rc::Int`: the return code is -1 in case of error, length of the response sent
     if successful.
"""
function modbus_reply(
    ctx::ModbusContext, req::AbstractVector{UInt8}, mbm_ptr::Ptr{ModbusMapping}
    )
    req_length = length(req)
    ret = ccall((:modbus_reply, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cint, Ptr{Cvoid}),
                ctx._ctx_ptr[], req, req_length, mbm_ptr)
    _strerror(ret, "modbus_reply()")

    return ret
end

"""
    modbus_tcp_listen(ctx::TcpContext, nb_connection::Integer) -> Int32

Create a socket and listen to maximum nb_connection incoming connections on the specified IP
address. The context ctx must be created and initialized by the constructor TcpContext().
If IP address is set to NULL or 0.0.0.0, any addresses will be listened to.

# Arguments
- `ctx::ModbusContext`: libmodbus TCP context
- `nb_connection::Integer`: maximum number of incoming connections.

# Returns
- `rc::Int`: the return code is -1 in case of error, a new socket if successful.
"""
function modbus_tcp_listen(ctx::TcpContext, nb_connection::Integer)
    ret = ccall((:modbus_tcp_listen, libmodbus), Cint, (Ptr{Cvoid}, Cint),
                ctx._ctx_ptr[], nb_connection)
    _strerror(ret, "modbus_tcp_listen()")

    return ret
end

"""
    modbus_tcp_accept(ctx::TcpContext, s::Int32) -> Int32

Extract the first connection on the queue of pending connections, create a new socket
and store it in the libmodbus context. 

See unit_test_server() function in tests for an example.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `s::Int32`: socket to listen on

# Returns
- `rc::Int`: the return code is -1 in case of error, new socket 
"""
function modbus_tcp_accept(ctx::TcpContext, s::Cint)
    ret = ccall((:modbus_tcp_accept, libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}),
                ctx._ctx_ptr[], s)
    _strerror(ret, "modbus_tcp_accept()")

    return ret
end

"""
    tcp_close(sockfd::Integer) -> Int32

Close Libc descriptor.

"""
function tcp_close(sockfd::Integer)
    ret = ccall(:close, Cint,(Cint,), sockfd)
    _strerror(ret, "tcp_close()")

    return ret
end

# RTU context
const MODBUS_RTU_RS232 = 0
const MODBUS_RTU_RS485 = 1
const MODBUS_RTU_RTS_NONE =  0
const MODBUS_RTU_RTS_UP = 1
const MODBUS_RTU_RTS_DOWN = 2

"""
    modbus_rtu_set_serial_mode(ctx::RtuContext, mode::Symbol) -> Int32

Set the selected serial mode:

MODBUS_RTU_RS232

- the serial line is set for RS232 communication. RS-232 (Recommended Standard 232)
is the traditional name for a series of standards for serial binary single-ended data
and control signals connecting between a DTE (Data Terminal Equipment) and
a DCE (Data Circuit-terminating Equipment). It is commonly used in computer serial ports

MODBUS_RTU_RS485

- the serial line is set for RS485 communication. EIA-485, also known as TIA/EIA-485
or RS-485, is a standard defining the electrical characteristics of drivers and receivers
for use in balanced digital multipoint systems. This standard is widely used
for communications in industrial automation because it enables commication over
long distances and in electrically noisy environments.


# Arguments
- `ctx::ModbusContext`: libmodbus context
- `mode::Symbol`: one of the symbols :RS485 or :RS232

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_rtu_set_serial_mode(ctx::RtuContext, mode::Symbol)
    if mode is :RS485
        m_code = MODBUS_RTU_RS485
    elseif mode is :RS232
        m_code = MODBUS_RTU_RS232
    else
        error("unknown serial mode")
    end
    ret = ccall((:modbus_rtu_set_serial_mode, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], m_code)
    _strerror(ret, "modbus_rtu_set_serial_mode()")

    return ret
end

"""
    modbus_rtu_get_serial_mode(ctx::RtuContext) -> Int32

Return the serial mode currently used by the libmodbus context as one of the symbols 
:RS232 or :RS485

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::RtuContext

# Returns
- `rc::Symbol`: the return code is :Nothing in case of error, seriall mode if successful.
"""
function modbus_rtu_get_serial_mode(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_serial_mode, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_rtu_get_serial_mode()")
    if ret == MODBUS_RTU_RS485
        mode = :RS485
    elseif ret == MODBUS_RTU_RS232
        mode = :RS232
    else
        @warn "unknown mode code returned by modbus_get_serial_mode()"
        mode = :Nothing
    end

    return mode
end

"""
    modbus_rtu_set_rts(ctx::RtuContext, mode::Symbol) -> Int32

Set the Request To Send mode to communicate on a RS485 serial bus. By default, the mode
is set to :RTS_NONE and no signal is issued before writing data on the wire.

To enable the RTS mode, the symbols :RTS_UP or :RTS_DOWN must be used, these modes
enable the RTS mode and set the polarity at the same time. When :RTS_UP is used,
an ioctl call is made with RTS flag enabled then data is written on the bus
after a delay of 1 ms, then another ioctl call is made with the RTS flag disabled
and again a delay of 1 ms occurs. The :RTS_DOWN mode applies the same procedure
but with an inverted RTS flag.

Can only be used with a context created by RtuContext() constructor.

# Arguments
- `ctx::ModbusContext`: libmodbus context created by the RtsContext() constructor
- `mode::Symbol`: Request To Send mode

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_rtu_set_rts(ctx::RtuContext, mode::Symbol)
    if mode is :RTS_NONE
        m_code = MODBUS_RTU_RTS_NONE
    elseif mode is :RTS_UP
        m_code = MODBUS_RTU_RTS_UP
    elseif mode is :RTS_DOWN
        m_code = MODBUS_RTU_RTS_DOWN
    else
        error("unknown rts mode")
    end
    ret = ccall((:modbus_rtu_set_rts_mode, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], m_code)
    _strerror(ret, "modbus_rtu_set_rts_mode()")

    return ret
end

"""
    modbus_rtu_get_rts(ctx::RtuContext) -> Symbol

Get the current Request To Send mode of the libmodbus context ctx. The possible returned
values are: :RTS_NONE, :RTS_UP, :RTS_DOWN and :Nothing

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Symbol`: the return is :Nothing in case of error, 0 if successful.
"""
function modbus_rtu_get_rts(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_rts, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_rtu_get_rts()")
    if ret == MODBUS_RTU_RTS_NONE
        mode = :RTS_NONE
    elseif ret == MODBUS_RTU_RTS_UP
        mode = :RTS_UP
    elseif ret == MODBUS_RTU_RTS_DOWN
        mode = :RTS_DOWN
    else
        @warn "unknown RTS code returned by modbus_get_rts()"
        mode = :Nothing
    end

    return mode
end

"""
    modbus_rtu_set_rts_delay(ctx::RtuContext, us::Int) -> Int32

Set the Request To Send delay period of the libmodbus context ctx.
This function can only be used with a context created by RtuContext() contructor.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `us::Int`:  Request To Send delay period in microseconds

# Returns
- `rc::Int`: the return code is -1 in case of error, 0 if successful.
"""
function modbus_rtu_set_rts_delay(ctx::RtuContext, us::Int)
    ret = ccall((:modbus_rtu_set_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], us)
    _strerror(ret, "modbus_rtu_set_rts_delay()")

    return ret
end

"""
    modbus_rtu_get_rts_delay(ctx::RtuContext) -> Int32

Get the current Request To Send delay period of the libmodbus context ctx.
This function can only be used with a context created by RtuContext() contructor.


# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
- `rc::Int`: the return code is -1 in case of error, the current RTS delay in microseconds
if successful.
"""
function modbus_rtu_get_rts_delay(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_rtu_get_rts_delay()")

    return ret
end

end
