"""
Management Layer: Decentralized Congestion Control (ETSI TS 102 687 V1.2.1).

* Reactive DCC (clause 5.3, Annex A): :mod:`.dcc_reactive`
* Adaptive DCC / LIMERIC and Gate Keeper (clause 5.4, Annex B): :mod:`.dcc_adaptive`
* Channel Busy Ratio sources from the access layer: :mod:`.cbr`
* DCC entity providing ``T_GenCam_DCC`` to the CA basic service: :mod:`.dcc_entity`

Mirrors ``rustflexstack::management``.
"""
