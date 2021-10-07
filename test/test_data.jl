# Values from modbus.h file of libmodbus
# Random number to avoid errno conflicts 
const MODBUS_ENOBASE =  112345678

# Protocol exceptions
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

const EMBXILFUN =   (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_ILLEGAL_FUNCTION))
const EMBXILADD =   (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS))
const EMBXILVAL =   (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE))
const EMBXSFAIL =   (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_SLAVE_OR_SERVER_FAILURE))
const EMBXACK =     (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_ACKNOWLEDGE))
const EMBXSBUSY =   (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY))
const EMBXNACK =    (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_NEGATIVE_ACKNOWLEDGE))
const EMBXMEMPAR =  (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_MEMORY_PARITY))
const EMBXGPATH =   (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_GATEWAY_PATH))
const EMBXGTAR =    (MODBUS_ENOBASE + UInt8(MODBUS_EXCEPTION_GATEWAY_TARGET))

# Native libmodbus error codes
const EMBBADCRC =   (EMBXGTAR + 1)
const EMBBADDATA =  (EMBXGTAR + 2)
const EMBBADEXC =   (EMBXGTAR + 3)
const EMBUNKEXC =   (EMBXGTAR + 4)
const EMBMDATA =    (EMBXGTAR + 5)
const EMBBADSLAVE =  (EMBXGTAR + 6)
# Values from tests/unit-test-server.h file of libmodbus
const UT_BITS_ADDRESS = 0x130
const UT_BITS_NB = 0x25
const UT_BITS_TAB = [ 0xCD, 0x6B, 0xB2, 0x0E, 0x1B ]

const UT_INPUT_BITS_ADDRESS = 0x1C4
const UT_INPUT_BITS_NB = 0x16
const UT_INPUT_BITS_TAB = [ 0xAC, 0xDB, 0x35 ]

const UT_REGISTERS_ADDRESS = 0x160
const UT_REGISTERS_NB = 0x3
const UT_REGISTERS_NB_MAX = 0x20
const UT_REGISTERS_TAB = [ 0x022B, 0x0001, 0x0064 ]

const UT_INPUT_REGISTERS_ADDRESS = 0x108
const UT_INPUT_REGISTERS_NB = 0x1
const UT_INPUT_REGISTERS_TAB = [ 0x000A ]

if !(@isdefined mbm)
    mbm = mapping_new_start_address(
        UT_BITS_ADDRESS, UT_BITS_NB,
        UT_INPUT_BITS_ADDRESS, UT_INPUT_BITS_NB,
        UT_REGISTERS_ADDRESS, UT_REGISTERS_NB_MAX,
        UT_INPUT_REGISTERS_ADDRESS, UT_INPUT_REGISTERS_NB
    )
end

"""
Idea from https://discourse.julialang.org/t/i-have-vector-uint8-i-need-bitvector/2286/5
"""
function make_bitvector(v::Vector{T}) where T<:Union{UInt8,UInt16,UInt32,UInt64}
    siz = sizeof(v)
    bv = falses(siz<<3)
    unsafe_copyto!(reinterpret(Ptr{UInt8}, pointer(bv.chunks)), pointer(v), siz)
    bv
end

for (k, x) in enumerate(UT_BITS_TAB)
    unsafe_store!(unsafe_load(mbm).tab_bits, x, k)
end
for (k, x) in enumerate(UT_INPUT_BITS_TAB)
    unsafe_store!(unsafe_load(mbm).tab_input_bits, x, k)
end
for (k, x) in enumerate(UT_INPUT_REGISTERS_TAB)
    unsafe_store!(unsafe_load(mbm).tab_input_registers, x, k)
end
for (k, x) in enumerate(UT_REGISTERS_TAB)
    unsafe_store!(unsafe_load(mbm).tab_registers, x, k)
end

if !(@isdefined(ctx) && modbus_context_valid(ctx))
    ctx = TcpContext("127.0.0.1", 1502)
end
# s = tcp_listen(mc, 1)
# tcp_accept(ctx, &s)

get_uint16(arr::Vector{UInt8}, k) = reinterpret(UInt16, arr[k:k+1])[]
set_uint16!(arr::Vector{UInt8}, k, val::UInt16) = arr[k:k+1] = reinterpret(UInt8, [val])

function unit_test_server(ctx::TcpContext, mbm::Ptr{ModbusMapping})
    hdr_length = get_header_length(ctx)
    srv = tcp_listen(ctx, 1)
    t = @task begin
        sa = tcp_accept(ctx, srv)
        println("sa = $(sa)")
        # while true
        #     while true
        #         ret_code,query = receive(ctx)
        #         ret_code == 0 || break
        #     end
        #     # do not clode connection on bad CRC
        #     if ret_code < 0 && ret_code != EMBBADCRC
        #         break;
        #     end
        #     # if query[header_length + 1] == 0x03
        #     #     println("Read holding registers")
        #     #     if get_int16(query, header_length + 4) == UT_REGISTERS_NB_SPECIAL
        #     #         println("Set an incorrect number of values")
        #     #         set_uint16!(query, header_length + 4, UT_REGISTERS_NB_SPECIAL - 1)
        #     #     elseif get_int16(query, header_length + 2)  == UT_REGISTERS_ADDRESS_SPECIAL
        #     #         prinln("Reply to this special register address by an exception")
        #     #         reply_exception(ctx, query, MODBUS_EXCEPTION_SLAVE_OR_SERVER_BUSY)
        #     #         continue
        #     #     elseif get_int16(query, header_length + 2) ==
        #     #         UT_REGISTERS_ADDRESS_INVALID_TID_OR_SLAVE
        #     #         raw_req = [0xFF, 0x03, 0x02, 0x00, 0x00]
        #     #         println("Reply with an invalid TID or slave")
        #     #         send_raw_request(ctx, raw_req)
        #     #         continue
        #     #     elseif get_int16(query, header_length + 2) ==
        #     #         UT_REGISTERS_ADDRESS_SLEEP_500_MS
        #     #         println("Sleep 0.5 s before replying\n")
        #     #         sleep(0.5)
        #     #     # elseif get_int16(query, header_length + 2)
        #     #     #     == UT_REGISTERS_ADDRESS_BYTE_SLEEP_5_MS
        #     #     #     # Test low level only available in TCP mode
        #     #     #     # Catch the reply and send reply byte a byte
        #     #     #     req = [0x00, 0x1C, 0x00, 0x00, 0x00, 0x05 ,0xFF, 0x03, 0x02, 0x00, 0x00]
        #     #     #     w_s = get_socket(ctx)
        #     #     #     if w_s == -1
        #     #     #         @warn "Unable to get a valid socket in special test"
        #     #     #         continue
        #     #     #     end
        #     #     #     # Copy TID
        #     #     #     req[1] = query[1];
        #     #     #     for i = 1:req_length
        #     #     #         printf("(%.2X)", req[i]);
        #     #     #         sleep(0.5)
        #     #     #         rc = send(w_s, (const char*)(req + i), 1, MSG_NOSIGNAL);
        #     #     #         if (rc == -1) 
        #     #     #             break;
        #     #     #         end
        #     #     #     end
        #     #     # continue;
        #     #     # end
        #     # end
        #     # continue
        #     rc = reply(ctx, query, rc, mb_mapping);
        #     rc >= 0 || break
        # end
        # println("Quit the loop") # $((errno)")
        # sa < 0 || close(sa)
    end
    # mapping_free(mb_mapping)
    # close(ctx)
    # free(ctx)

    return t,srv
end
