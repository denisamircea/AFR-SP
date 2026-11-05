# Sprint 1: first version of the sensor handler. Logs only event id and a hash of the state.
def on_reading(logger, reading, event_id):
    logger.info("event %s state %s", event_id, state_hash(reading))
    logger.info("temp %s battery %s", reading["temp_c"], reading["batt_pct"])
