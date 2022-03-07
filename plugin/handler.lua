-- dynamic routing based on JWT Claim
local sub = string.sub
local type = type
local pairs = pairs
local lower = string.lower

local jwt_decoder = require "kong.plugins.jwt.jwt_parser"

local JWT2Header = {
    PRIORITY = 900,
    VERSION = "1.0"
}

function JWT2Header:rewrite(conf)
    kong.service.request.set_header("X-Kong-JWT-Kong-Proceed", "no")
    kong.log.debug(kong.request.get_header("Authorization"))
    local claims = nil
    local header = nil

    if kong.request.get_header("Authorization") ~= nil then
        kong.log.debug(kong.request.get_header("Authorization"))
        if string.match(lower(kong.request.get_header("Authorization")), 'bearer') ~= nil then
            kong.log.debug("2" .. kong.request.get_path())
            local jwt, err = jwt_decoder:new((sub(kong.request.get_header("Authorization"), 8)))
            if err then
                return false, {
                    status = 401,
                    message = "Bad token; " .. tostring(err)
                }
            end

            claims = jwt.claims
            header = jwt.header
            kong.service.request.set_header("X-Kong-JWT-Kong-Proceed", "yes")
        end
    end

    if kong.request.get_header("X-Kong-JWT-Kong-Proceed") == "yes" then
        for claim, value in pairs(claims) do
            local claimHeader = toHeaderKey(claim)
            local valueHeader = toHeaderValue(value)
            kong.service.request.set_header("X-Kong-JWT-Claim-" .. claimHeader, valueHeader)
        end
    end

end

function JWT2Header:access(conf)
    if kong.request.get_header("X-Kong-JWT-Kong-Proceed") == "yes" then
        -- ctx oesn't work in kong 1.5, only in 2.x local claims = kong.ctx.plugin.claims
        local claims = kong.request.get_headers();
        if not claims then
            kong.log.debug("empty claim")
            return
        end

        if conf.strip_claims == "true" then
            for claim, value in pairs(claims) do
                kong.log.debug("found header " .. claim)
                if type(claim) == "string" and string.match(claim, 'x%-kong%-jwt%-claim') ~= nil then
                    kong.service.request.clear_header(claim)
                    kong.log.debug("removed header " .. claim)
                end
            end
            kong.service.request.clear_header("X-Kong-JWT-Kong-Proceed")
        end

        -- kong.ctx.plugin.claims = nil
    elseif conf.token_required == "true" then
        kong.service.request.clear_header("X-Kong-JWT-Kong-Proceed")
        kong.response.exit(404, '{"error": "No valid JWT token found"}')
    else
        kong.service.request.clear_header("X-Kong-JWT-Kong-Proceed")

    end
end

-- converts a key to a header compatible key
function toHeaderKey(key)
    local stringkey = tostring(key)

    -- quick and dirty pascal casing
    local words = {}
    for i, v in pairs(strsplit(stringkey, "_")) do -- grab all the words separated with a _ underscore
        table.insert(words, v:sub(1, 1):upper() .. v:sub(2)) -- we take the first character, uppercase, and add the rest. Then I insert to the table
    end

    return table.concat(words, "") -- just concat everything inside of the table
end

-- converts a value to a header compatible value
-- will convert bool/numbers to strings, join arrays with ",", etc.
function toHeaderValue(value)
    if type(value) == "string" then
        return value
    end

    if type(value) == "boolean" then
        return tostring(value)
    end

    if type(value) == "number" then
        return tostring(value) -- might want to use string.format instead?
    end

    if type(value) == "nil" then
        return ""
    end

    if type(value) == "table" then
        if value[1] == nil then
            -- do something here to create string from dictionary table
            local joineddict = {}

            for k, val in pairs(value) do
                table.insert(joineddict, tostring(k) .. "=" .. tostring(val))
            end

            return table.concat(joineddict, ",")
        end

        return table.concat(value, ",") -- array value can be simply joined
    end

    return tostring(value)
end

function strsplit(inputstr, sep)
    if sep == nil then
        sep = "%s"
    end

    local t = {}
    for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
        table.insert(t, str)
    end

    return t
end

return JWT2Header
