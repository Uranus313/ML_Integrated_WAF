local _M = {}

function _M.new()
    return { score = 0, reasons = {} }
end

function _M.add(state, amount, reason)
    state.score = state.score + amount
    table.insert(state.reasons, reason)
end

function _M.should_block(state, threshold)
    return state.score >= (threshold or 5)
end

return _M
