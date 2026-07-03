local raw_request = require("feature_extraction.raw_request")
local logger      = require("feature_extraction.logger")

local extractors = {
    require("feature_extraction.features.metadata"),
    require("feature_extraction.features.http_method"),
    require("feature_extraction.features.header.header_fingerprint"),
    require("feature_extraction.features.header.header_lengths"),
    require("feature_extraction.features.header.header_presence"),
    require("feature_extraction.features.header.header_statistics"),

}

local M = {}

function M.run()

    -- 1. Build transaction
    local tx = raw_request.read()

    -- 2. Run feature extractors
    for _, extractor in ipairs(extractors) do
        extractor.extract(tx)
    end

    -- 3. LOG IT (dataset creation step)
    logger.write(tx)

    return tx
end

return M