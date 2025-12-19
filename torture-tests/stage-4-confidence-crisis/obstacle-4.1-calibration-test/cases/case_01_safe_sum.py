def safe_sum(numbers: list[int]) -> int:
    total = 0
    for value in numbers:
        total += int(value)
    return total
