# Sprint 3: after the gate failed, the debug line is rewritten without the personal field.
def on_reading(logger, reading, event_id):
    logger.info("event %s state %s", event_id, state_hash(reading))
    logger.info("temp %s battery %s", reading["temp_c"], reading["batt_pct"])
    logger.debug("reading accepted (event %s)", event_id)
