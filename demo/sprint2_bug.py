# Sprint 2: a developer adds a "helpful" debug line that prints who the reading belongs to.
def on_reading(logger, reading, event_id):
    logger.info("event %s state %s", event_id, state_hash(reading))
    logger.info("temp %s battery %s", reading["temp_c"], reading["batt_pct"])
    logger.debug("reading from %s (event %s)", reading["user_email"], event_id)
