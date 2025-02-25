# pylint: skip-file
ETSI_ITS_DSRC_REGION_ASN1_DESCRIPTIONS = """
--! @options: no-fields-header

ETSI-ITS-DSRC-REGION {
  itu-t (0) identified-organization (4) etsi (0) itsDomain (5) wg1 (1) ts103301 (103301) dsrc (6) region (1) major-version-2 (2) minor-version-1 (1)
}

DEFINITIONS AUTOMATIC TAGS::= BEGIN

IMPORTS

addGrpC, REG-EXT-ID-AND-TYPE
FROM ETSI-ITS-DSRC {
  itu-t (0) identified-organization (4) etsi (0) itsDomain (5) wg1 (1) ts103301 (103301) dsrc (6) major-version-2 (2) minor-version-1 (1)
}

ConnectionManeuverAssist-addGrpC, ConnectionTrajectory-addGrpC,
IntersectionState-addGrpC, LaneAttributes-addGrpC, MapData-addGrpC,
MovementEvent-addGrpC, NodeAttributeSet-addGrpC, Position3D-addGrpC, RequestorDescription-addGrpC, RestrictionUserType-addGrpC, SignalStatusPackage-addGrpC
FROM ETSI-ITS-DSRC-AddGrpC {
  itu-t (0) identified-organization (4) etsi (0) itsDomain (5) wg1 (1) ts103301 (103301) dsrc (6) addgrpc (0) major-version-2 (2) minor-version-1 (1)
};

Reg-AdvisorySpeed	            REG-EXT-ID-AND-TYPE ::= { ... }

Reg-ComputedLane	            REG-EXT-ID-AND-TYPE ::= { ... }

Reg-ConnectionManeuverAssist	REG-EXT-ID-AND-TYPE ::= {
	{ConnectionManeuverAssist-addGrpC  IDENTIFIED BY addGrpC},
	...
}

Reg-GenericLane	                REG-EXT-ID-AND-TYPE ::= {
	{ConnectionTrajectory-addGrpC	IDENTIFIED BY addGrpC} ,
	...
}

Reg-IntersectionGeometry  	    REG-EXT-ID-AND-TYPE ::= { ... }

Reg-IntersectionState           REG-EXT-ID-AND-TYPE ::= {
	{IntersectionState-addGrpC IDENTIFIED BY addGrpC},
	...
}

Reg-LaneAttributes	            REG-EXT-ID-AND-TYPE ::= {
   {LaneAttributes-addGrpC IDENTIFIED BY addGrpC} ,
   ...
}
Reg-LaneDataAttribute           REG-EXT-ID-AND-TYPE ::= { ... }

Reg-MapData	                    REG-EXT-ID-AND-TYPE ::= {
	{MapData-addGrpC  IDENTIFIED BY addGrpC},
	...
}

Reg-MovementEvent	            REG-EXT-ID-AND-TYPE ::= {
   {MovementEvent-addGrpC IDENTIFIED BY addGrpC} ,
   ...
}
Reg-MovementState               REG-EXT-ID-AND-TYPE ::= { ... }


Reg-NodeAttributeSetXY          REG-EXT-ID-AND-TYPE ::= {
	{NodeAttributeSet-addGrpC   IDENTIFIED BY addGrpC},
	...
}

Reg-NodeOffsetPointXY	        REG-EXT-ID-AND-TYPE ::= { ... }

Reg-Position3D	                REG-EXT-ID-AND-TYPE ::= {
	{Position3D-addGrpC  IDENTIFIED BY addGrpC} ,
	...
}

Reg-RequestorDescription        REG-EXT-ID-AND-TYPE ::= {
   { RequestorDescription-addGrpC IDENTIFIED BY addGrpC} ,
   ...
}

Reg-RequestorType	            REG-EXT-ID-AND-TYPE ::= { ... }

Reg-RestrictionUserType	        REG-EXT-ID-AND-TYPE ::= {
  {RestrictionUserType-addGrpC IDENTIFIED BY addGrpC} ,
  ...
}

Reg-RoadSegment	                REG-EXT-ID-AND-TYPE ::= { ... }

Reg-RTCMcorrections             REG-EXT-ID-AND-TYPE ::= { ... }

Reg-SignalControlZone           REG-EXT-ID-AND-TYPE ::= { ... }

Reg-SignalRequest               REG-EXT-ID-AND-TYPE ::= { ... }

Reg-SignalRequestMessage        REG-EXT-ID-AND-TYPE ::= { ... }

Reg-SignalRequestPackage        REG-EXT-ID-AND-TYPE ::= { ... }

Reg-SignalStatus	            REG-EXT-ID-AND-TYPE ::= { ... }

Reg-SignalStatusMessage	        REG-EXT-ID-AND-TYPE ::= { ... }

Reg-SignalStatusPackage	        REG-EXT-ID-AND-TYPE ::= {
	{ SignalStatusPackage-addGrpC IDENTIFIED BY addGrpC },
	...
}

Reg-SPAT	                    REG-EXT-ID-AND-TYPE ::= { ... }

END
    
"""
