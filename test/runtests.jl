using AWS
using AWS: AWSCredentials
using AWS: AWSServices
using AWS.AWSExceptions: AWSException, InvalidFileName, NoCredentials, ProtocolNotDefined
using AWS.AWSMetadata: _clean_documentation, _filter_latest_service_version,
    _generate_low_level_definition, _generate_high_level_definition, _generate_high_level_definitions,
    _get_aws_sdk_js_files, _get_service_and_version, _get_function_parameters, _clean_uri, _format_name,
    _splitline, _wraplines, _validindex
using Base64
using Compat: mergewith
using Dates
using GitHub
using HTTP
using IniFile: Inifile
using JSON
using OrderedCollections: LittleDict, OrderedDict
using MbedTLS: digest, MD_SHA256, MD_MD5
using Mocking
using Pkg
using Random
using Retry
using Suppressor
using Test
using UUIDs
using XMLDict

Mocking.activate()

include("patch.jl")

aws = AWSConfig()

function _now_formatted()
    return lowercase(Dates.format(now(Dates.UTC), dateformat"yyyymmdd\THHMMSSsss\Z"))
end


@testset "Retrieving AWS Credentials" begin
    test_values = Dict{String, Any}(
        "Default-Profile" => "default",
        "Test-Profile" => "test",
        "Test-Config-Profile" => "profile test",

        # Default profile values, needs to match due to AWSCredentials.jl check_credentials()
        "AccessKeyId" => "Default-Key",
        "SecretAccessKey" => "Default-Secret",

        "Test-AccessKeyId" => "Test-Key",
        "Test-SecretAccessKey" => "Test-Secret",

        "Token" => "Test-Token",
        "InstanceProfileArn" => "Test-Arn",
        "RoleArn" => "Test-Arn",
        "Expiration" => now(UTC) + Minute(7),

        "URI" => "/Test-URI/",
        "Security-Credentials" => "Test-Security-Credentials"
    )

    println("Initial Expiration Value; ", test_values["Expiration"])

    _http_request_patch = @patch function HTTP.request(method::String, url; kwargs...)
        security_credentials = test_values["Security-Credentials"]
        uri = test_values["URI"]
        url = string(url)

        if url == "http://169.254.169.254/latest/meta-data/iam/info"
            instance_profile_arn = test_values["InstanceProfileArn"]
            return  HTTP.Response("{\"InstanceProfileArn\": \"$instance_profile_arn\"}")
        elseif url == "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            return  HTTP.Response(test_values["Security-Credentials"])
        elseif url == "http://169.254.169.254/latest/meta-data/iam/security-credentials/$security_credentials" || url == "http://169.254.170.2$uri"
            my_dict = JSON.json(test_values)
            response = HTTP.Response(my_dict)
            return response
        else
            return nothing
        end
    end

    @testset "Instance - EC2" begin
        role_name = "foobar"
        role_arn = "arn:aws:sts::1234:assumed-role/$role_name"
        access_key = "access-key-$(randstring(6))"
        secret_key = "secret-key-$(randstring(6))"
        session_token = "session-token-$(randstring(6))"
        session_name = "$role_name-session"
        patch = Patches._assume_role_patch(
            "AssumeRole";
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            role_arn=role_arn,
        )

        apply([patch, _http_request_patch]) do
            result = mktemp() do config_file, config_io
                write(
                    config_io,
                    """
                    [profile $role_name]
                    credential_source = Ec2InstanceMetadata
                    role_arn = $role_arn
                    """
                )
                close(config_io)

                withenv("AWS_CONFIG_FILE" => config_file, "AWS_ROLE_SESSION_NAME" => session_name) do
                    ec2_instance_credentials(role_name)
                end
            end

            @test result.access_key_id == access_key
            @test result.secret_key == secret_key
            @test result.token == session_token
            @test result.user_arn == role_arn * "/" * session_name
            @test result.renew !== nothing
            expiry = result.expiry

            result = check_credentials(result)

            @test result.access_key_id == access_key
            @test result.secret_key == secret_key
            @test result.token == session_token
            @test result.user_arn == role_arn * "/" * session_name
            @test result.renew !== nothing
            @test expiry != result.expiry
        end
    end
end

exit()

@testset "AWS.jl" begin
    include("AWS.jl")
    include("AWSCredentials.jl")
    include("AWSExceptions.jl")
    include("AWSMetadataUtilities.jl")
    include("issues.jl")
    include("test_pkg.jl")
    include("utilities.jl")

    if haskey(ENV, "TEST_MINIO")
        include("minio.jl")
    end
end
