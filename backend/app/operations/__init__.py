"""Operational planning for the judge demo.

The security-event approval flow records intent and does not call external
systems. This package plans the judge script beside that flow. Delivery stays
in recording mode until OPERATIONS_DELIVERY=live and the channel credentials
are present.
"""
