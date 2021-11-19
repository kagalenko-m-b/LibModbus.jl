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

struct TcpContext <: ModbusContext
    ip_address::String
    port::Int
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

modbus_context_valid(ctx::ModbusContext) = ctx._ctx_ptr[] != C_NULL

function Base.show(io::IO, ctx::TcpContext)
    color = modbus_context_valid(ctx) ? :green : :red
    str = modbus_context_valid(ctx) ? "ip $(ctx.ip_address), port $(ctx.port)" : "NULL"
    printstyled(io, "TcpContext($(str))"; color)
end

struct RtuContext <: ModbusContext
    device::String
    baud::Integer
    parity::Symbol
    data_bit::Integer
    stop_bit::Integer
    _ctx_ptr::Ref{Ptr{Modbus_t}}
    function RtuContext(
        device::String,
        baud::Integer,
        parity::Symbol,
        data_bit::Integer,
        stop_bit::Integer
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
        ctx_ptr = ccall((:modbus_new_rtu, libmodbus), Ptr{Modbus_t},
                        (Cstring, Cint, Cchar, Cint, Cint),
                        device, baud, prt, data_bit, stop_bit)
        if ctx_ptr == C_NULL
            _strerror(-1, "RtuContext()")
        end
        ctx = new(device, baud, parity, data_bit, stop_bit, ctx_ptr)
        return ctx
    end
end

function Base.show(io::IO, ctx::RtuContext)
    color = modbus_context_valid(ctx) ? :green : :red
    str =  modbus_context_valid(ctx) ? "RtuContext(device $(ctx.device), baud $(ctx.baud), "*
        "parity $(ctx.parity)), data_bit $(ctx.data_bit), stop_bit $(ctx.stop_bit))" : "NULL"
    printstyled(io, str; color)
end

# Common for RTU and TCP contexts
"""
    modbus_set_slave(ctx::ModbusContext, slave::Integer) -> Integer

Set the slave number in the libmodbus context 

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, slave::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_set_slave(ctx::ModbusContext, slave::Integer)
    ret = ccall((:modbus_set_slave, libmodbus), Cint, (Ptr{Cvoid}, Cint),
                ctx._ctx_ptr[], slave)
    _strerror(ret, "modbus_set_slave()")

    return ret
end

"""
    modbus_get_slave(ctx::ModbusContext) -> Integer

Get the slave number in the libmodbus context.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
-`rc::Int`: slave number if successful, otherwise return -1 and set errno
"""
function modbus_get_slave(ctx::ModbusContext)
    ret = ccall((:modbus_get_slave, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_slave()")

    return ret
end

"""
    modbus_set_socket!(ctx::ModbusContext, s::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, s::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_set_socket!(ctx::ModbusContext, s::Integer)
    ret = ccall((:modbus_set_socket, libmodbus), Cint, (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], s)
    _strerror(ret, "modbus_set_socket!()")

    return ret
end

"""
    modbus_get_socket(ctx::ModbusContext) -> Integer

Get the current socket of the context 

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
-`rc::Int`: current socket or file descriptor of the context if successful,
    otherwise return -1 and set errno
"""
function modbus_get_socket(ctx::ModbusContext)
    ret = ccall((:modbus_get_socket, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_socket()")

    return ret
end


"""
    modbus_get_response_timeout(ctx::ModbusContext) -> Integer,Int,Int

Get timeout interval used to wait for a response

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
-`to_sec::Int`: seconds of the response timeout
-`to_usec`: microseconds of the response timeout
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
                                                                                    -> Integer

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
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_set_response_timeout(ctx::ModbusContext,  to_sec::Integer, to_usec::Integer)
    ret = ccall((:modbus_set_response_timeout, libmodbus), Cint,
                (Ptr{Cvoid}, UInt32, UInt32), ctx._ctx_ptr[], to_sec, to_usec)
    _strerror(ret, "modbus_set_response_timeout()")

    return ret
end

"""
    modbus_get_byte_timeout(ctx::ModbusContext) -> Integer,Int,Int

Timeout interval between two consecutive bytes of the same message 

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
-`to_sec::Int`: seconds of the byte timeout
-`to_usec`: microseconds of the byte timeout
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
    modbus_set_byte_timeout(ctx::ModbusContext, to_sec::Integer, to_usec::Integer) -> Integer

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
-`to_sec::Int`: seconds of the byte timeout
-`to_usec`: microseconds of the byte timeout

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
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
    modbus_set_error_recovery(ctx::ModbusContext, err_rec::Integer) -> Integer

Set the error recovery mode to apply when the connection fails or the byte received is not
expected. The argument error_recovery may be bitwise-or’ed with zero or more
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

It’s not recommended to enable error recovery for slave/server.

# Arguments
- `ctx::ModbusContext`: libmodbus context
-`to_sec::Int`: seconds of the byte timeout
-`to_usec`: microseconds of the byte timeout

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function  modbus_set_error_recovery(ctx::ModbusContext, err_rec::Integer)
    ret = ccall((:modbus_set_error_recovery, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], Cint(err_rec))
    _strerror(ret, "modbus_set_error_recovery()")

    return ret
end

"""
    modbus_get_header_length(ctx::ModbusContext) -> Integer

Retrieve the current header length from the backend. 

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
-`rc::Int`: the header length as an integer value, negative in case of error.
"""
function modbus_get_header_length(ctx::ModbusContext)
    ret = ccall((:modbus_get_header_length, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_get_header_length()")

    return ret
end

"""
    modbus_connect(ctx::ModbusContext) -> Integer

Establish a connection to a Modbus server, a network or a bus using the context information
of libmodbus context given in argument.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_connect(ctx::ModbusContext)
    ret = ccall((:modbus_connect, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_connect()")

    return ret
end

"""
    modbus_close(ctx::ModbusContext)

Close the connection established with the backend set in the context.

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
ctx::ModbusContext

# Returns
nothing
"""
function modbus_free!(ctx::ModbusContext)
    ccall((:modbus_free, libmodbus), Cvoid, (Ptr{Cvoid},), ctx._ctx_ptr[])
    ctx._ctx_ptr[] = C_NULL

    return nothing
end

"""
    modbus_flush(ctx::ModbusContext) -> Integer

Discard data received but not read to the socket or file descriptor associated
to the context.

# Arguments
- `ctx::ModbusContext`: libmodbus context

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_flush(ctx::ModbusContext)
    ret = ccall((:modbus_flush, libmodbus), Cint, (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_flush()")

    return ret
end

"""
    modbus_set_debug(ctx::ModbusContext, flag::Bool) -> Integer

Set the debug flag of the context. By default, the boolean flag is set to false.
When the flag value is set to true, many verbose messages are displayed.

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `flag::Bool`: display debug information if true

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_set_debug(ctx::ModbusContext, flag::Bool)
    ret = ccall((:modbus_set_debug, libmodbus), Cint, (Ptr{Cvoid},Cint),
                ctx._ctx_ptr[], flag)
    _strerror(ret, "modbus_set_debug()")

    return ret
end

function _strerror(return_code::Integer, message::AbstractString)
    err_no = Libc.errno()
    if return_code < 0
        return_code = err_no
        str = ccall((:modbus_strerror,libmodbus), Cstring, (Cint,), err_no)
        @warn "$(message): "*unsafe_string(str)
    end

    return nothing
end

"""
    modbus_read_bits(ctx::ModbusContext, addr::Integer, nb::Integer) -> Integer,Vector

Read the status of the nb bits (coils) at the address addr of the remote device and
return a vector of the results as unsigned bytes, one per each logical value.

The function uses the Modbus function code 0x01 (read coil status).

# Arguments
- `ctx::ModbusContext`: libmodbus context
- `addr::Integer`: address to begin reading at
- `nb::Integer`: number of coil to read

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.

"""
function modbus_read_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}),
                ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_bits()")
    # bv = ret > 0 ? BitVector(dest[1:ret]) : BitVector[]

    return ret,dest[1:ret]
end

"""
    modbus_read_input_bits(ctx::ModbusContext, addr::Integer, nb::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, addr::Integer, nb::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_read_input_bits(ctx::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_input_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}),
                ctx._ctx_ptr[], addr, nb, dest)
    _strerror(ret, "modbus_read_input_bits()")

    return ret,dest[1:ret]
end

"""
    modbus_read_registers(ctx::ModbusContext, addr::Integer, nb::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, addr::Integer, nb::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
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
    modbus_read_input_registers(ctx::ModbusContext, addr::Integer, nb::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, addr::Integer, nb::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
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
    modbus_write_bit(ctx::ModbusContext, coil_addr::Integer, status::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, coil_addr::Integer, status::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_write_bit(ctx::ModbusContext, coil_addr::Integer, status::Integer)
    ret = ccall((:modbus_write_bit, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint), ctx._ctx_ptr[], coil_addr, status)
    _strerror(ret, "modbus_write_bit()")

    return ret
end

"""
    modbus_write_register(ctx::ModbusContext, reg_addr::Integer, value::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, reg_addr::Integer, value::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_write_register(ctx::ModbusContext, reg_addr::Integer, value::Integer)
    ret = ccall((:modbus_write_register, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16), ctx._ctx_ptr[], reg_addr, value)
    _strerror(ret, "modbus_write_register()")

    return ret
end

function modbus_write_bits(
    ctx::ModbusContext, addr::Integer, data::AbstractVector{UInt8}
    )
    nb = length(data)
    ret = ccall((:modbus_write_bits, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), ctx._ctx_ptr[], addr, nb, data)
    _strerror(ret, "modbus_write_bits()")
    ret <= 0 || ret == nb || @warn "wrote $(ret) bits instead of $(nb)"

    return ret
end

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

function modbus_send_raw_request(
    ctx::ModbusContext, raw_req::AbstractVector{UInt8}
    )
    nb = length(raw_req)
    ret = ccall((:modbus_send_raw_request, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cint),
                ctx._ctx_ptr[], raw_req, nb)
    _strerror(ret, "modbus_send_raw_request()")

    return ret
end

function modbus_reply_exception(
    ctx::ModbusContext, req::AbstractVector{UInt8}, exception_code::MbExcpt
    )
    ret = ccall((:modbus_reply_exception, libmodbus), Cint,
                (Ptr{Cvoid}, Ref{UInt8}, Cuint),
                ctx._ctx_ptr[], req, exception_code)
    #int modbus_reply_exception(modbus_t *ctx, const uint8_t *req, unsigned int exception_code);
end

"""
    modbus_report_slave_id(ctx::ModbusContext, max_dest::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::ModbusContext, max_dest::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_report_slave_id(ctx::ModbusContext, max_dest::Integer)
    dest = Vector{UInt8}(undef, max_dest)
    ret = ccall((:modbus_report_slave_id, libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Ref{UInt8}), ctx._ctx_ptr[], max_dest, dest)
    _strerror(ret, "modbus_report_slave_id()")
    ret <= max_dest || @warn "$(ret) bytes of output truncated to $(max_dest)"

    return ret, dest[1:min(max_dest, ret)]
end

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

function modbus_mapping_free!(mbm_ptr::Ptr{ModbusMapping})
    ccall((:modbus_mapping_free, libmodbus), Cvoid,
          (Ptr{ModbusMapping},), mbm_ptr)
end

"""
    modbus_receive(ctx::TcpContext) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::TcpContext

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_receive(ctx::TcpContext)
    req = Vector{UInt8}(undef, MODBUS_TCP_MAX_ADU_LENGTH)
    ret = ccall((:modbus_receive, libmodbus), Cint, (Ptr{Cvoid}, Ref{UInt8}),
                ctx._ctx_ptr[], req)
    _strerror(ret, "modbus_receive()")

    return ret,req[1:ret]
end

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

# TCP context
"""
    modbus_tcp_listen(ctx::TcpContext, nb_connection::Integer) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::TcpContext, nb_connection::Integer

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_tcp_listen(ctx::TcpContext, nb_connection::Integer)
    ret = ccall((:modbus_tcp_listen, libmodbus), Cint, (Ptr{Cvoid}, Cint),
                ctx._ctx_ptr[], nb_connection)
    _strerror(ret, "modbus_tcp_listen()")

    return ret
end

"""
    modbus_tcp_accept(ctx::TcpContext, s::Cint) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::TcpContext, s::Cint

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_tcp_accept(ctx::TcpContext, s::Cint)
    ret = ccall((:modbus_tcp_accept, libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}),
                ctx._ctx_ptr[], s)
    _strerror(ret, "modbus_tcp_accept()")

    return ret
end

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
    modbus_rtu_set_serial_mode(ctx::RtuContext, mode::Symbol) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::RtuContext, mode::Symbol

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
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
    modbus_rtu_get_serial_mode(ctx::RtuContext) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::RtuContext

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
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
    modbus_rtu_set_rts(ctx::RtuContext, mode::Symbol) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::RtuContext, mode::Symbol

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
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
    modbus_rtu_get_rts(ctx::RtuContext) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::RtuContext

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
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
    modbus_rtu_set_rts_delay(ctx::RtuContext, us::Int) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::RtuContext, us::Int

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_rtu_set_rts_delay(ctx::RtuContext, us::Int)
    ret = ccall((:modbus_rtu_set_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid}, Cint), ctx._ctx_ptr[], us)
    _strerror(ret, "modbus_rtu_set_rts_delay()")

    return ret
end

"""
    modbus_rtu_get_rts_delay(ctx::RtuContext) -> Integer

Function to ...

# Arguments
- `ctx::ModbusContext`: libmodbus context
ctx::RtuContext

# Returns
-`rc::Int`: the return code is negative in case of error, 0 if successful.
"""
function modbus_rtu_get_rts_delay(ctx::RtuContext)
    ret = ccall((:modbus_rtu_get_rts_delay, libmodbus), Cint,
                (Ptr{Cvoid},), ctx._ctx_ptr[])
    _strerror(ret, "modbus_rtu_get_rts_delay()")

    return ret
end

end
