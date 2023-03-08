using Distributed
using Test

(@isdefined verbose) || (verbose = false)
# Create separate process to run the unit test TCP server
srv_proc = addprocs(1)[]
@everywhere begin
    using Pkg
    Pkg.activate("LibModbus")
    Pkg.instantiate()
    using LibModbus
    include("unit_test_constants.jl")
    include("unit_test_functions.jl")
    include("unit_test_server.jl")
end
include("unit_test_client.jl")
fetch(@spawnat srv_proc @eval Main mb_mapping=init_server_mapping())
fetch(@spawnat srv_proc @eval Main ctx_server = TcpContext("127.0.0.1", 1502))
is_verbose = false
remote_do(()->start_unit_test_server(ctx_server, mb_mapping, verbose=is_verbose), srv_proc)
unit_test_client(verbose)
rmprocs(srv_proc)
