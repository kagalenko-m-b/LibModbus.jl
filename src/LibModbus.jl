module LibModbus

export ConnectionType, ModbusContext
export modbus_new_tcp, modbus_connect, modbus_read_registers, modbus_write_register
export odbus_write_registers
export modbus_close,modbus_free

mutable struct Modbus_t end

abstract type ConnectionType end
struct TCP <: ConnectionType end
struct RTU <: ConnectionType end

const MODBUS_MAX_ADU_LENGTH = 260
const MODBUS_RTU_MAX_ADU_LENGTH = 256

max_adu_length(::TCP) = MODBUS_TCP_MAX_ADU_LENGTH
max_adu_length(::RTU) = MODBUS_RTU_MAX_ADU_LENGTH

struct ModbusContext{T<:ConnectionType}
    _ctx::Ptr{Modbus_t}
    function _create_context(ctx::Ptr{Modbus_t},::Type{T}) where T
        if ctx == C_NULL
            error("Error creating Modbus context: "*Libc.strerror(Libc.errno()))
        end
        mc = new{T}(ctx)
    end
    function ModbusContext(ip_address::String, port::Integer)
        ctx = ccall((:modbus_new_tcp, :libmodbus), Ptr{Modbus_t}, (Cstring, Cint),
                    ip_address, port)
        if ctx == C_NULL
            error("Error creating Modbus TCP context: "*Libc.strerror(Libc.errno()))
        end
        _create_context(ctx, TCP)
    end
    function ModbusContext(
        device::AbstractString,
        baud::Integer,
        parity::Symbol,
        data_bit::Integer,
        stop_bit::Integer)
        if parity is :none
            prt = 'N'
        elseif parity is :even
            prt = 'E'
        elseif parity is :odd
            prt = 'O'
        else
            error("unknown parity value specified")
        end
        ctx = ccall((:modbus_new_rtu, :libmodbus), Ptr{Modbus_t},
                    (Cstring, Cint, Cchar, Cint, Cint),
                    device, baud, prt, data_bit, stop_bit);
        _create_context(ctx, RTU)
    end
end

Base.setproperty!(v::ModbusContext, name::Symbol, x) = error("no user settable properties")


function modbus_tcp_listen(mc::ModbusContext{TCP}, nb_connection::Integer)
    ret = ccall((:modbus_tcp_listen, :libmodbus), Cint, (Ptr{Cvoid}, Cint),
                mc._ctx, nb_connection)
    ret >= 0 || error("error creating socket: "*modbus_strerror(Libc.errno()))

    return ret
end

function modbus_tcp_accept(mc::ModbusContext{TCP}, s::Integer)
    ret = ccall((:modbus_tcp_accept, :libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}), mc._ctx, s)
    ret >= 0 || error("error accepting connection: "*modbus_strerror(Libc.errno()))

    return ret
end

function modbus_receive(mc::ModbusContext{T}) where T::ConnectionType
    req = Vector{UInt8}(undef, max_adu_length(T))
    ret = ccall((:modbus_receive, :libmodbus), Cint, (Ptr{Cvoid}, Ref{UInt8}), mc._ctx, req)
    ret >= 0 || error("error receiving indication request: "*modbus_strerror(Libc.errno()))

    return req
end

function modbus_reply(mc::ModbusContext, req::Vector{UInt8}, modbus_mapping_t *mb_mapping)

  # int
end

function modbus_set_slave(mc::ModbusContext, slave::Integer)
    ret = ccall((:modbus_set_slave, :libmodbus), Cint, (Ptr{Cvoid}, Ref{Cint}),
                mc._ctx, slave)
    ret >= 0 || error("error setting slave number: "*Libc.strerror(Libc.errno()))

    return nothing
end

function modbus_get_slave(mc::ModbusContext)
    ccall((:modbus_get_slave, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
end

function modbus_set_socket!(mc::ModbusContext, s::Integer)
    ret = ccall((:modbus_set_socket, :libmodbus), Cint, (Ptr{Cvoid}, Cint), mc._ctx, s)
    ret == 0 || @warn "error setting socket: "*Libc.strerror(Libc.errno())

    return nothing
end

function modbus_get_socket(mc::ModbusContext)
    ret = ccall((:modbus_get_socket, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
    ret == 0 || @warn "error getting socket: "*Libc.strerror(Libc.errno())

    return ret
end

"""
function modbus_set_response_timeout(mc::ModbusContext, uint32_t to_sec, uint32_t to_usec)

  # int
end

function modbus_get_response_timeout(mc::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

  # int
end



function modbus_get_byte_timeout(mc::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

  # int
end

function modbus_set_byte_timeout(mc::ModbusContext, uint32_t to_sec, uint32_t to_usec)

  # int
end


function modbus_get_indication_timeout(mc::ModbusContext, uint32_t *to_sec, uint32_t *to_usec)

  # int
end

function modbus_set_indication_timeout(mc::ModbusContext, uint32_t to_sec, uint32_t to_usec)

  # int
end


function modbus_get_header_length(mc::ModbusContext)

  # int
end
"""

function modbus_connect(mc::ModbusContext)
    ret = ccall((:modbus_connect, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
    ret == 0 || @warn "connection error: "*modbus_strerror(ret)

    return ret
end

function modbus_close(mc::ModbusContext)
    ccall((:modbus_close, :libmodbus), Cvoid, (Ptr{Cvoid},), mc._ctx)
end

function modbus_free(mc::ModbusContext)
    ccall((:modbus_free, :libmodbus), Cvoid, (Ptr{Cvoid},), mc._ctx)
end

function modbus_flush(mc::ModbusContext)
    ccall((:modbus_flush, :libmodbus), Cint, (Ptr{Cvoid},), mc._ctx)
end

function modbus_strerror(errnum::Integer)
    unsafe_string(ccall((:modbus_strerror,:libmodbus), Cstring, (Cint,), errnum))
end

function modbus_read_registers(mc::ModbusContext, addr::Integer, nb::Integer)
    dest = Vector{UInt16}(undef, nb)
    ret = ccall((:modbus_read_registers, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), mc._ctx, addr, nb, dest)
    ret >= 0 || @warn "error reading registers: "*modbus_strerror(ret)
    ret == nb || @warn "read $(ret) registers instead of $(nb)"

    return dest[1:ret]
end

function modbus_write_register(mc::ModbusContext, reg_addr::Integer, value::Integer)
    ret = ccall((:modbus_write_register, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, UInt16), mc._ctx, reg_addr, value)
    ret == 1 || @warn "error writing register: "*modbus_strerror(Libc.errno())

    return ret
end

function modbus_write_registers(
    mc::ModbusContext, addr::Integer, data::AbstractVector{UInt16}
    )
    nb = length(data)
    ret = ccall((:modbus_write_registers, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), mc._ctx, addr, nb, data)
    ret >= 0 || @warn "error writing registers: "*modbus_strerror(Libc.errno())
    ret == nb || @warn "wrote $(ret) registers instead of $(nb)"

    return ret
end

function modbus_read_bits(mc::ModbusContext, addr::Integer, nb::Integer)#, uint8_t *dest)
    dest = Vector{UInt8}(undef, nb)
    ret = ccall((:modbus_read_bits, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt16}), mc._ctx, addr, nb, dest)
    ret >= 0 || @warn "error reading bits: "*modbus_strerror(Libc.errno())

    return ret
end

function modbus_write_bit(mc::ModbusContext, coil_addr::Integer, status::Integer)
    ret = ccall((:modbus_write_bit, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint), mc._ctx, coil_addr, status)
    ret == 1 || @warn "error writing bit: "*modbus_strerror(Libc.errno())

    return ret
end

function modbus_write_bits(mc::ModbusContext, addr::Integer, data::Vector{UInt8})
    nb = length(data)
    ret = ccall((:modbus_write_bits, :libmodbus), Cint,
                (Ptr{Cvoid}, Cint, Cint, Ref{UInt8}), mc._ctx, addr, nb, data)
    ret >= 0 || @warn "error writing bits: "*modbus_strerror(Libc.errno())
    ret == nb || @warn "wrote $(ret) bits instead of $(nb)"

    return ret
  # int
end


"""
function modbus_mask_write_register(mc::ModbusContext, addr::Integer, uint16_t and_mask, uint16_t or_mask)

  # int
end

function modbus_write_and_read_registers(mc::ModbusContext, write::Integer_addr, write::Integer_nb, const uint16_t *src, read::Integer_addr, read::Integer_nb, uint16_t *dest)

  # int
end
                                       
function modbus_report_slave_id(mc::ModbusContext, max::Integer_dest, uint8_t *dest)

  # int
end


function modbus_send_raw_request(mc::ModbusContext, const uint8_t *raw_req, raw::Integer_req_length)

  # int
end



function modbus_receive_confirmation(mc::ModbusContext, uint8_t *rsp)

  # int
end



function modbus_reply_exception(mc::ModbusContext, const uint8_t *req, unsigned exception::Integer_code)

  # int
end
"""

end
