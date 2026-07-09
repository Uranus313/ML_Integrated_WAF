local entropy = require("feature_extraction.utils.entropy")
local M = {}

function M.extract(tx)

    local f = tx.features
    local query = tx.raw_request.query or {}

    local parameter_count = 0

    local total_name_length = 0
    local largest_name_length = 0
    
    local all_parameter_names = {}
    local all_parameter_values = {}

    local special_character_count = 0
    local total_value_characters = 0
    local total_value_length = 0
    local largest_value_length = 0

    local empty_parameter_count = 0
    local duplicate_parameter_count = 0
    local numeric_parameter_count = 0
    local encoded_parameter_count = 0


    local query_contains_directory_traversal = 0
    
    for name, value in pairs(query) do

        parameter_count = parameter_count + 1

        local name = tostring(name)
        local name_length = #name
        table.insert(all_parameter_names, name)
        
        total_name_length = total_name_length + name_length

        if name_length > largest_name_length then
            largest_name_length = name_length
        end

        local values

        if type(value) == "table" then
            duplicate_parameter_count =
                duplicate_parameter_count + (#value - 1)

            values = value
        else
            values = { value }
        end

        for _, v in ipairs(values) do

            v = tostring(v or "")
            table.insert(all_parameter_values, v)
           
            local len = #v

            total_value_length =
                total_value_length + len

            if len > largest_value_length then
                largest_value_length = len
            end

            if len == 0 then
                empty_parameter_count =
                    empty_parameter_count + 1
            end

            if tonumber(v) ~= nil then
                numeric_parameter_count =
                    numeric_parameter_count + 1
            end

            if v:find("%%", 1, true) then
                encoded_parameter_count =
                    encoded_parameter_count + 1
            end
            total_value_characters =
                total_value_characters + #v

            local _, specials =
                v:gsub("[^%w]", "")

            special_character_count =
                special_character_count + specials
            
            if v:find("..", 1, true) then
            query_contains_directory_traversal = 1
            end 
        end
    end

    f.query_contains_directory_traversal = query_contains_directory_traversal
    f.parameter_count = parameter_count

    if parameter_count > 0 then
        f.average_parameter_name_length =
            total_name_length / parameter_count

        f.average_parameter_value_length =
            total_value_length / parameter_count
    else
        f.average_parameter_name_length = 0
        f.average_parameter_value_length = 0
    end

    f.largest_parameter_name_length =
        largest_name_length

    f.largest_parameter_value_length =
        largest_value_length

    f.empty_parameter_count =
        empty_parameter_count

    f.duplicate_parameter_count =
        duplicate_parameter_count

    f.numeric_parameter_count =
        numeric_parameter_count

    f.encoded_parameter_count =
        encoded_parameter_count

    ------------------------------------------------------------
    -- Entropy
    ------------------------------------------------------------

    f.parameter_name_entropy =
        entropy.compute(table.concat(all_parameter_names, "&"))

    f.parameter_value_entropy =
        entropy.compute(table.concat(all_parameter_values, "&"))

    ------------------------------------------------------------
    -- Special character ratio
    ------------------------------------------------------------

    if total_value_characters > 0 then
        f.parameter_special_character_ratio =
            special_character_count / total_value_characters
    else
        f.parameter_special_character_ratio = 0
    end    
end

return M