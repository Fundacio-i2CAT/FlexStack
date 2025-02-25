# pylint: skip-file
ETSI_ITS_DSRC_ASN1_DESCRIPTIONS="""
--! @options: no-fields-header

ETSI-ITS-DSRC {
  itu-t (0) identified-organization (4) etsi (0) itsDomain (5) wg1 (1) ts103301 (103301) dsrc (6) major-version-2 (2) minor-version-1 (1)
}

DEFINITIONS AUTOMATIC TAGS::= BEGIN

IMPORTS

Longitude, Latitude, StationID, Iso3833VehicleType
FROM ETSI-ITS-CDD {
  itu-t (0) identified-organization (4) etsi (0) itsDomain (5) wg1 (1) 102894 cdd (2) major-version-4 (4) minor-version-2 (2)
}

Reg-AdvisorySpeed, Reg-ComputedLane, Reg-ConnectionManeuverAssist, Reg-GenericLane,
Reg-IntersectionGeometry, Reg-IntersectionState, Reg-LaneAttributes, Reg-MapData,
Reg-LaneDataAttribute, Reg-MovementEvent, Reg-MovementState,
Reg-NodeAttributeSetXY, Reg-NodeOffsetPointXY, Reg-Position3D, Reg-RequestorDescription, Reg-RequestorType, Reg-RestrictionUserType, Reg-RoadSegment,
Reg-RTCMcorrections, Reg-SignalControlZone, Reg-SignalRequestPackage, Reg-SignalRequest, Reg-SignalStatus, Reg-SignalStatusPackage, Reg-SignalRequestMessage,
Reg-SignalStatusMessage, Reg-SPAT
FROM ETSI-ITS-DSRC-REGION {
  itu-t (0) identified-organization (4) etsi (0) itsDomain (5) wg1 (1) ts103301 (103301) dsrc (6) region (1) major-version-2 (2) minor-version-1 (1)
};

/**
* This information object class is an abstract template to instantiate region extension.
*
* @field &id: the identifier of the region type.
* @field &Type: the extension content
*
* @category: Basic Information
* @revision: V1.3.1
*/
REG-EXT-ID-AND-TYPE ::= CLASS {
  &id     RegionId UNIQUE,
  &Type
} WITH SYNTAX {&Type IDENTIFIED BY &id}

/**
* This DF represents a Region extension preceded by its type identifier and a lenght indicator.
*
* It shall include the following components:
*
* @field regionId: the identifier of the region.
* @field regExtValue: the extension content consistent with the region type.
*
* @category: Basic Information
* @revision: V1.3.1
*/
RegionalExtension {REG-EXT-ID-AND-TYPE : Set} ::= SEQUENCE {
  regionId     REG-EXT-ID-AND-TYPE.&id( {Set} ),
  regExtValue  REG-EXT-ID-AND-TYPE.&Type( {Set}{@regionId} )
}

/**
* This DF is used to convey many types of geographic road information. At the current time its primary
* use is to convey one or more intersection lane geometry maps within a single message. The map message content
* includes such items as complex intersection descriptions, road segment descriptions, high speed curve outlines (used in
* curve safety messages), and segments of roadway (used in some safety applications). A given single MapData message
* may convey descriptions of one or more geographic areas or intersections. The contents of this message involve defining
* the details of indexing systems that are in turn used by other messages to relate additional information (for example, the
* signal phase and timing via the SPAT message) to events at specific geographic locations on the roadway.
*
* @field timeStamp: time reference
* @field msgIssueRevision: The MapData revision is defined by the data element **revision** for each intersection
*                          geometry (see [ISO TS 19091] G.8.2.4.1). Therefore, an additional revision indication of the overall
*                          MapData message is not used in this profile. It shall be set to "0" for this profile.
* @field layerType: There is no need to additionally identify the topological content by an additional identifier. The ASN.1
*                   definition of the data frames **intersections** and **roadSegments** are clearly defined and need no
*                   additional identifier. Therefore, this optional data element shall not be used in this profile.
* @field layerID: This profile extends the purpose of the **layerID** data element as defined in SAE J2735 as follows: For
*                 large intersections, the length of a MapData description may exceed the maximum data length of the
*                 communication message. Therefore, a fragmentation of the MapData message (at application layer) in
*                 two or more MapData fragments may be executed. If no MapData fragmentation is needed, the **layerID**
*                 shall not be used. For more details, see the definition of the data element @ref LayerID.
* @field intersections: All Intersection definitions.
* @field roadSegments: All roadway descriptions.
* @field dataParameters: Any meta data regarding the map contents.
* @field restrictionList: Any restriction ID tables which have established for these map entries
* @field regional: This profile extends the MapData message with the regional data element @ref MapData-addGrpC
*
* @category: Road topology information
* @revision: V1.3.1
*/
MapData ::= SEQUENCE {
  timeStamp         MinuteOfTheYear OPTIONAL,
  msgIssueRevision  MsgCount,
  layerType         LayerType OPTIONAL,
  layerID           LayerID  OPTIONAL,
  intersections     IntersectionGeometryList OPTIONAL,
  roadSegments      RoadSegmentList OPTIONAL,
  dataParameters    DataParameters OPTIONAL,
  restrictionList   RestrictionClassList OPTIONAL,
  regional          SEQUENCE (SIZE(1..4)) OF
                    RegionalExtension {{Reg-MapData}} OPTIONAL,
  ...
}

/**
* This DF is used to encapsulate RTCM differential corrections for GPS and other radio
* navigation signals as defined by the RTCM (Radio Technical Commission For Maritime Services) special committee
* number 104 in its various standards. Here, in the work of DSRC, these messages are "wrapped" for transport on the
* DSRC media, and then can be re-constructed back into the final expected formats defined by the RTCM standard and
* used directly by various positioning systems to increase the absolute and relative accuracy estimates produced.
*
* @field msgCnt: monotonic incrementing identifier.
* @field rev: the specific edition of the standard that is being sent.
* @field timeStamp: time reference
* @field anchorPoint: Observer position, if needed.
* @field rtcmHeader: Precise antenna position and noise data for a rover
* @field msgs: one or more RTCM messages.
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RTCMcorrections ::= SEQUENCE {
   msgCnt      MsgCount,
   rev         RTCM-Revision,
   timeStamp   MinuteOfTheYear  OPTIONAL,
   anchorPoint FullPositionVector OPTIONAL,
   rtcmHeader  RTCMheader OPTIONAL,
   msgs        RTCMmessageList,
   regional    SEQUENCE (SIZE(1..4)) OF
               RegionalExtension {{Reg-RTCMcorrections}} OPTIONAL,
   ...
}

/**
* This DF is used to convey the current status of one or more signalized
* intersections. Along with the MapData message (which describes a full geometric layout of an intersection) the
* receiver of this message can determine the state of the signal phasing and when the next expected phase will occur.
* The SPAT message sends the current movement state of each active phase in the system as needed (such as values of
* what states are active and values at what time a state has begun/does begin earliest, is expected to begin most likely and
* will end latest). The state of inactive movements is not normally transmitted. Movements are mapped to specific
* approaches and connections of ingress to egress lanes and by use of the SignalGroupID in the MapData message
*
* The current signal preemption and priority status values (when present or active) are also sent. A more complete
* summary of any pending priority or preemption events can be found in the Signal Status message.
*
* @field timeStamp: time reference
* @field name: human readable name for this collection. to be used only in debug mode.
* @field intersections: sets of SPAT data (one per intersection)
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SPAT ::= SEQUENCE {
  timeStamp     MinuteOfTheYear OPTIONAL,
  name          DescriptiveName OPTIONAL,
  intersections IntersectionStateList,
  regional      SEQUENCE (SIZE(1..4)) OF
                RegionalExtension {{Reg-SPAT}} OPTIONAL,
  ...
}

/**
* This DF is a message sent by a DSRC equipped entity (such as a vehicle) to the RSU in a
* signalized intersection. It is used for either a priority signal request or a preemption signal request depending on the way
* each request is set. Each request defines a path through the intersection which is desired in terms of lanes and
* approaches to be used. Each request can also contain the time of arrival and the expected duration of the service.
* Multiple requests to multiple intersections are supported. The requestor identifies itself in various ways (using methods
* supported by the @refRequestorDescription data frame), and its current speed, heading and location can be placed in this
* structure as well. The specific request for service is typically based on previously decoding and examining the list of lanes
* and approaches for that intersection (sent in MAP messages). The outcome of all of the pending requests to a signal can
* be found in the Signal Status Message (SSM), and may be reflected in the SPAT message contents if successful.
*
* @field timeStamp: time reference
* @field second: time reference
* @field sequenceNumber: monotonic incrementing identifier
* @field requests: Request Data for one or more signalized intersections that support SRM dialogs
* @field requestor: Requesting Device and other User Data contains vehicle ID (if from a vehicle) as well as type data and current
*                   position and may contain additional transit data
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalRequestMessage ::= SEQUENCE {
  timeStamp       MinuteOfTheYear  OPTIONAL,
  second          DSecond,
  sequenceNumber  MsgCount         OPTIONAL,
  requests        SignalRequestList OPTIONAL,
  requestor       RequestorDescription,
  regional        SEQUENCE (SIZE(1..4)) OF
                  RegionalExtension {{Reg-SignalRequestMessage}} OPTIONAL,
  ...
}

/**
* This DF is a message sent by an RSU in a signalized intersection. It is used to relate the current
* status of the signal and the collection of pending or active preemption or priority requests acknowledged by the controller.
* It is also used to send information about preemption or priority requests which were denied. This in turn allows a dialog
* acknowledgment mechanism between any requester and the signal controller. The data contained in this message allows
* other users to determine their "ranking" for any request they have made as well as to see the currently active events.
* When there have been no recently received requests for service messages, this message may not be sent. While the
* outcome of all pending requests to a signal can be found in the Signal Status Message, the current active event (if any)
* will be reflected in the SPAT message contents.
*
* @field timeStamp: time reference
* @field second: time reference
* @field sequenceNumber: monotonic incrementing identifier
* @field status: Status Data for one of more signalized intersections.
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalStatusMessage ::= SEQUENCE {
  timeStamp       MinuteOfTheYear  OPTIONAL,
  second          DSecond,
  sequenceNumber  MsgCount         OPTIONAL,
  status          SignalStatusList,
  regional        SEQUENCE (SIZE(1..4)) OF
                  RegionalExtension {{Reg-SignalStatusMessage}} OPTIONAL,
  ...
}

/**
* This DF is used to convey a recommended traveling approach speed to an intersection
* from the message issuer to various travelers and vehicle types. Besides support for various eco-driving applications, this
* allows transmitting recommended speeds for specialty vehicles such as transit buses.
*
* @field type: the type of advisory which this is.
* @field speed: See @ref SpeedAdvice for converting and translating speed expressed in mph into units of m/s.
*               This element is optional ONLY when superceded by the presence of a regional speed element found in Reg-AdvisorySpeed entry
* @field confidence: A confidence value for the above speed
* @field distance: The distance indicates the region for which the advised speed is recommended, it is specified upstream from the stop bar
*                  along the connected egressing lane. Unit = 1 meter 
* @field class: the vehicle types to which it applies when absent, the AdvisorySpeed applies to all motor vehicle types
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
AdvisorySpeed ::= SEQUENCE {
  type        AdvisorySpeedType,
  speed       SpeedAdvice OPTIONAL,
  confidence  SpeedConfidenceDSRC OPTIONAL,
  distance    ZoneLength OPTIONAL,
  class       RestrictionClassID OPTIONAL,
  regional    SEQUENCE (SIZE(1..4)) OF
              RegionalExtension {{Reg-AdvisorySpeed}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of @ref AdvisorySpeed entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
AdvisorySpeedList ::= SEQUENCE (SIZE(1..16)) OF AdvisorySpeed

/**
* This DF is a collection of three offset values in an orthogonal coordinate system
* which describe how far the electrical phase center of an antenna is in each axis from a nearby known anchor point in units of 1 cm.
*
* When the antenna being described is on a vehicle, the signed offset shall be in the coordinate system defined in section 11.4.
*
* @field antOffsetX: a range of +- 20.47 meters.
* @field antOffsetY: a range of +- 2.55 meters.
* @field antOffsetZ: a range of +- 5.11 meters.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
AntennaOffsetSet ::= SEQUENCE {
   antOffsetX  Offset-B12,
   antOffsetY  Offset-B09,
   antOffsetZ  Offset-B10
}

/**
* This DE is used to contain information needed to compute one lane from another
* (hence the name). This concept is used purely as a means of saving size in the message payload. The new lane is
* expressed as an X,Y offset from the first point of the source lane. It can be optionally rotated and scaled. Any attribute
* information found within the node of the source lane list cannot be changed and must be reused.
*
* @field referenceLaneId: the lane ID upon which this computed lane will be based Lane Offset in X and Y direction
* @field offsetXaxis: A path X offset value for translations of the path's points when creating translated lanes.
* @field offsetYaxis: The values found in the reference lane are all offset based on the X and Y values from
*                     the coordinates of the reference lane's initial path point.
* @field rotateXY: A path rotation value for the entire lane
*                  Observe that this rotates the existing orientation
*                  of the referenced lane, it does not replace it.
*                  Rotation occurs about the initial path point.
* @field scaleXaxis: value for translations or zooming of the path's points. The values found in the reference lane
* @field scaleYaxis: are all expanded or contracted based on the X and Y and width values from the coordinates of  the reference lane's initial path point.
*                    The Z axis remains untouched.
* @field regional: optional region specific data.
*
* @note: The specified transformation shall be applied to the reference lane without any intermediary loss of precision
*        (truncation). The order of the transformations shall be: the East-West and North-South offsets, the scaling factors, and
*        finally the rotation.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
ComputedLane ::= SEQUENCE {
  referenceLaneId    LaneID,
  offsetXaxis        CHOICE {
                        small   DrivenLineOffsetSm,
                        large   DrivenLineOffsetLg
                        },
  offsetYaxis        CHOICE {
                        small   DrivenLineOffsetSm,
                        large   DrivenLineOffsetLg
                        },
  rotateXY           Angle OPTIONAL,
  scaleXaxis         Scale-B12 OPTIONAL,
  scaleYaxis         Scale-B12 OPTIONAL,
  regional  SEQUENCE (SIZE(1..4)) OF
            RegionalExtension {{Reg-ComputedLane}} OPTIONAL,
  ...
}

/**
* This DF is used in the generic lane descriptions to provide a sequence of other defined
* lanes to which each lane connects beyond its stop point. See the Connection data frame entry for details. Note that this
* data frame is not used in some lane object types.
*
* @note: The assignment of lanes in the Connection structure shall start with the leftmost lane from the vehicle
*   perspective (the u-turn lane in some cases) followed by subsequent lanes in a clockwise assignment order. Therefore, the
*   rightmost lane to which this lane connects would always be listed last. Note that this order is observed regardless of which
*   side of the road vehicles use. If this structure is used in the lane description, then all valid lanes to which the subject lane
*   connects shall be listed.
* @category: Infrastructure information
* @revision: V1.3.1
*/
ConnectsToList ::= SEQUENCE (SIZE(1..16)) OF Connection

/**
* The data concept ties a single lane to a single maneuver needed to reach it from another lane.
* It is typically used to connect the allowed maneuver from the end of a lane to the outbound lane so that these can be
* mapped to the SPAT message to which both lanes apply.
*
* @field lane: Index of the connecting lane.
*
* @field maneuver: This data element allows only the description of a subset of possible manoeuvres and therefore
*    represents an incomplete list of possible travel directions. The connecting **lane** data element gives the
*    exact information about the manoeuvre relation from ingress to egress lane. Therefore the "maneuver"
*    data element may be used only additionally if the travel direction of the manoeuvre is unanmbigoulsy
*    represented (e.g. left, right, straight, etc.).
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
ConnectingLane ::= SEQUENCE {
  lane      LaneID,
  maneuver  AllowedManeuvers OPTIONAL
}

/**
* This DF is used to combine/connect multiple physical lanes (i.e. within intersections or road
* segments). For signalized movements, the **connectsTo** data frame defines e.g. the relation between
* ingress and egress lanes within an intersection. It describes the allowed manoeuvres and includes the
* link (**signalGroup** identifier) between the @ref MapData and the @ref SPAT message. The data frame is also used
* to describe the relation of lanes within a non signalized intersection (e.g. ingress lanes which are
* bypassing the conflict area and ending in an egress lane without signalization). Within a road segment,
* it is used to combine two or multiple physical lanes into a single lane object.
*
* @field connectingLane: 
* @field remoteIntersection: When the data element **remoteIntersection** is used, it indicates
*                            that the connecting lane belongs to another intersection. 
*                            (see clause [ISO TS 19091] G.9.1 for further explainations).
* @field signalGroup: 
* @field userClass: 
* @field connectionID: 
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Connection ::= SEQUENCE {
  connectingLane     ConnectingLane,
  remoteIntersection IntersectionReferenceID OPTIONAL,
  signalGroup        SignalGroupID OPTIONAL,
  userClass          RestrictionClassID OPTIONAL,
  connectionID       LaneConnectionID OPTIONAL
}

/**
* This DF contains information about the the dynamic flow of traffic for the lane(s)
* and maneuvers in question (as determined by the @ref LaneConnectionID). Note that this information can be sent regarding
* any lane-to-lane movement; it need not be limited to the lanes with active (non-red) phases when sent.
*
* @field connectionID: the common connectionID used by all lanes to which this data applies
*                     (this value traces to ConnectsTo entries in lanes)
*
* @field queueLength: The distance from the stop line to the back edge of the last vehicle in the queue,
*                     as measured along the lane center line. (Unit = 1 meter, 0 = no queue)
*
* @field availableStorageLength: Distance (e.g. beginning from the downstream stop-line up to a given distance) with a high
*                     probability for successfully executing the connecting maneuver between the two lanes
*                     during the current cycle.
*                     Used for enhancing the awareness of vehicles to anticipate if they can pass the stop line
*                     of the lane. Used for optimizing the green wave, due to knowledge of vehicles waiting in front
*                     of a red light (downstream).
*                     The element nextTime in @ref TimeChangeDetails in the containing data frame contains the next
*                     timemark at which an active phase is expected, a form of storage flush interval.
*                     (Unit = 1 meter, 0 = no space remains)
*
* @field waitOnStop:  If true, the vehicles on this specific connecting
*                     maneuver have to stop on the stop-line and not to enter the collision area
*
* @field pedBicycleDetect: true if ANY ped or bicycles are detected crossing the above lanes. Set to false ONLY if there is a
*                     high certainty that there are none present, otherwise element is not sent.
*
* @field regional:    This data element includes additional data content @ref ConnectionManeuverAssist-addGrpC defined in
*                     this profile (see [ISO TS 19091] G.5.1.1). The content is included using the regional extension framework as defined in
*                     @ref ConnectionManeuverAssist-addGrpC is used for position feedback to moving ITS stations for executing
*                     safe manoeuvres and is included for this purpose in the data element "intersectionState"
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
ConnectionManeuverAssist ::= SEQUENCE {
  connectionID         LaneConnectionID,
  queueLength          ZoneLength OPTIONAL,
  availableStorageLength ZoneLength OPTIONAL,
  waitOnStop           WaitOnStopline OPTIONAL,
  pedBicycleDetect     PedestrianBicycleDetect OPTIONAL,
  regional  SEQUENCE (SIZE(1..4)) OF
            RegionalExtension {{Reg-ConnectionManeuverAssist}} OPTIONAL,
  ...
}

/**
* This DF is used to provide basic (static) information on how a map fragment was processed or determined.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
DataParameters ::= SEQUENCE {
  processMethod     IA5String(SIZE(1..255)) OPTIONAL,
  processAgency     IA5String(SIZE(1..255)) OPTIONAL,
  lastCheckedDate   IA5String(SIZE(1..255)) OPTIONAL,
  geoidUsed         IA5String(SIZE(1..255)) OPTIONAL,
  ...
}

/**
* The DSRC style date is a compound value consisting of finite-length sequences of integers (not characters) of the
* form: "yyyy, mm, dd, hh, mm, ss (sss+)" - as defined below.
*
* @note: Note that some elements of this structure may not be sent when not needed. At least one element shall be present.
* @category: Infrastructure information
* @revision: V1.3.1
*/
DDateTime ::= SEQUENCE {
   year    DYear    OPTIONAL,
   month   DMonth   OPTIONAL,
   day     DDay     OPTIONAL,
   hour    DHour    OPTIONAL,
   minute  DMinute  OPTIONAL,
   second  DSecond  OPTIONAL,
   offset  DOffset  OPTIONAL
 }

/**
* This DF is a sequence of lane IDs for lane objects that are activated in the current map
* configuration. These lanes, unlike most lanes, have their RevocableLane bit set to one (asserted). Such lanes are not
* considered to be part of the current map unless they are in the Enabled Lane List. This concept is used to describe all the
* possible regulatory states for a given physical lane. For example, it is not uncommon to enable or disable the ability to
* make a right hand turn on red during different periods of a day. Another similar example would be a lane which is used for
* driving during one period and where parking is allowed at another. Traditionally, this information is conveyed to the vehicle
* driver by local signage. By using the Enabled Lane List data frame in conjunction with the RevocableLane bit and
* constructing a separate lane object in the intersection map for each different configuration, a single unified map can be
* developed and used.
*
* Contents are the unique ID numbers for each lane object which is **active** as part of the dynamic map contents.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
EnabledLaneList ::= SEQUENCE (SIZE(1..16)) OF LaneID

/**
* A complete report of the vehicle's position, speed, and heading at an instant in time. Used in the probe vehicle
* message (and elsewhere) as the initial position information. Often followed by other data frames that may provide offset
* path data.
*
* @field utcTime:   time with mSec precision
* @field long:      Longitude in 1/10th microdegree
* @field lat:       Latitude in 1/10th microdegree
* @field elevation: Elevation in units of 0.1 m
* @field heading:   Heading value 
* @field speed:     Speed value
* @field posAccuracy:      position accuracy
* @field timeConfidence:   time confidence
* @field posConfidence:    position confidence
* @field speedConfidence:  speed confidence 
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
FullPositionVector ::= SEQUENCE {
   utcTime             DDateTime OPTIONAL,
   long                Longitude,
   lat                 Latitude,
   elevation           Elevation  OPTIONAL,
   heading             HeadingDSRC OPTIONAL,
   speed               TransmissionAndSpeed OPTIONAL,
   posAccuracy         PositionalAccuracy OPTIONAL,
   timeConfidence      TimeConfidence OPTIONAL,
   posConfidence       PositionConfidenceSet OPTIONAL,
   speedConfidence     SpeedandHeadingandThrottleConfidence OPTIONAL,
   ...
}

/**
* This DF is used for all types of lanes, e.g. motorized vehicle lanes, crosswalks, medians. The
* GenericLane describes the basic attribute information of the lane. The LaneID value for each lane is unique within an
* intersection. One use for the LaneID is in the SPAT message, where a given signal or movement phase is mapped to a
* set of applicable lanes using their respective LaneIDs. The NodeList2 data frame includes a sequence of offset points (or
* node points) representing the center line path of the lane. As described in this standard, node points are sets of variable
* sized delta orthogonal offsets from the prior point in the node path. (The initial point is offset from the LLH anchor point
* used in the intersection.) Each node point may convey optional attribute data as well. The use of attributes is described
* further in the Node definition, and in a later clause, but an example use would be to indicate a node point where the lane
* width changes.
*
* It should be noted that a "lane" is an abstract concept that can describe objects other than motorized vehicle lanes, and
* that the generic lane structure (using features drawn from Japanese usage) also allows combining multiple physical lanes
* into a single lane object. In addition, such lanes can describe connectivity points with other lanes beyond a single
* intersection, extending such a lane description over multiple nearby physical intersections and side streets which
* themselves may not be equipped or assigned an index number in the regional intersection numbering system. (See the
* ConnectsTo entry for details) This has value when describing a broader service area in terms of the roadway network,
* probably with less precision and detail.
*
* @field laneID:  The unique ID number assigned to this lane object
* @field name:    often for debug use only but at times used to name ped crossings
* @field ingressApproach:  inbound Approach ID to which this lane belongs
* @field egressApproach: outbound Approach ID to which this lane belongs
* @field laneAttributes: All Attribute information about the basic selected lane type
*                        Directions of use, Geometric co-sharing and Type Specific Attributes
*                        These Attributes are **lane - global** that is, they are true for the entire length of the lane
* @field maneuvers: This data element allows only the description of a subset of possible manoeuvres and therefore
*                    reperesents an incomplete list of possible travel directions. The connecting **lane** data element gives
*                    the exact information about the manoeuvre relation from ingress to egress lane. Therefore the
*                    "maneuver" data element is used only additionally if the travel direction of the manoeuvre is
* @field nodeList: Lane spatial path information as well as various Attribute information along the node path
*                    Attributes found here are more general and may come and go over the length of the lane.
* @field connectsTo: a list of other lanes and their signal group IDs each connecting lane and its signal group ID
*                    is given, therefore this element provides the information formerly in "signalGroups" in prior editions.
* @field overlays: A list of any lanes which have spatial paths that overlay (run on top of, and not simply cross)
*                    the path of this lane when used
* @field regional: optional region specific data.
*
* @note: The data elements **ingressApproach** and **egressApproach** are used for grouping lanes whin an
*       approach (e.g. lanes defined in travel direction towards the intersection, lanes in exiting direction and
*       cross walks). For a bidirectrional lane (e.g. bike lane) both dataelements are used for the same lane. The
*       integer value used for identifying the **ingressApproach** and the **egressAproach**, based on the
*       topology, may be e.g. the same for all lanes within an approach of an intersection.
* @category: Infrastructure information
* @revision: V1.3.1
*/
GenericLane ::= SEQUENCE {
  laneID           LaneID,
  name             DescriptiveName OPTIONAL,
  ingressApproach  ApproachID OPTIONAL,
  egressApproach   ApproachID OPTIONAL,
  laneAttributes   LaneAttributes,
  maneuvers        AllowedManeuvers OPTIONAL,
  nodeList         NodeListXY,
  connectsTo       ConnectsToList OPTIONAL,
  overlays         OverlayLaneList OPTIONAL,
  regional  SEQUENCE (SIZE(1..4)) OF
            RegionalExtension {{Reg-GenericLane}} OPTIONAL,
  ...
}

/**
* This DF is used to specify the index of either a single approach or a single lane at
* which a service is needed. This is used, for example, with the Signal Request Message (SRM) to indicate the inbound
* and outbound points by which the requestor (such as a public safety vehicle) can traverse an intersection.
*
* @field lane: the representation of the point as lane identifier.
* @field approach: the representation of the point as approach identifier.
* @field connection: the representation of the point as connection identifier.
*
* @note: Note that the value of zero has a reserved meaning for these two indexing systems. In both cases, this value
*    is used to indicate the concept of "none" in use. When the value is of zero is used here, it implies the center of the
*    intersection itself. For example, requesting an outbound point of zero implies the requestor wishes to have the intersection
*    itself be the destination. Alternatively, an inbound value of zero implies the requestor is within the intersection itself and
*    wishes to depart for the outbound value provided. This special meaning for the value zero can be used in either the lane
*    or approach with the same results.
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionAccessPoint ::= CHOICE {
  lane       LaneID,
  approach   ApproachID,
  connection LaneConnectionID,
  ...
}

/**
* A complete description of an intersection's roadway geometry and its allowed navigational paths (independent of
* any additional regulatory restrictions that may apply over time or from user classification).
*
* @field name: For debug use only
* @field id: A globally unique value set, consisting of a regionID and intersection ID assignment
* @field revision: This profile extends the purpose of the **revision** data element as defined in SAE J2735 as follows.
*           The revision data element is used to communicate the valid release of the intersection geometry
*           description. If there are no changes in the deployed intersection description, the same revision counter
*           is transmitted. Due to a revised deployment of the intersection description (e.g. new lane added, ID's
*           changed, etc.), the revision is increased by one. After revision equal to 127, the increment restarts by 0.
*           The intersection geometry and the signal phase and timing information is related each other. Therefore,
*           the revision of the intersection geometry of the MapData message shall be the same as the revision of
*           the intersection state of the SPAT (see data element **revision** of **DF_IntersectionState** in [ISO TS 19091] G.8.2.9)
* @field refPoint: The reference from which subsequent data points are offset until a new point is used.
* @field laneWidth: Reference width used by all subsequent lanes unless a new width is given
* @field speedLimits: Reference regulatory speed limits used by all subsequent lanes unless a new speed is given
* @field laneSet: Data about one or more lanes (all lane data is found here) Data describing how to use and request preemption and
*           priority services from this intersection (if supported)
* @field preemptPriorityData: This DF is not used.
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionGeometry ::= SEQUENCE {
  name        DescriptiveName OPTIONAL,
  id          IntersectionReferenceID,
  revision    MsgCount,
  refPoint    Position3D,
  laneWidth   LaneWidth OPTIONAL,
  speedLimits SpeedLimitList OPTIONAL,
  laneSet     LaneList,
  preemptPriorityData PreemptPriorityList OPTIONAL,
  regional     SEQUENCE (SIZE(1..4)) OF
               RegionalExtension {{Reg-IntersectionGeometry}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of IntersectionGeometry entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionGeometryList ::= SEQUENCE (SIZE(1..32)) OF IntersectionGeometry

/**
* This DF conveys the combination of an optional RoadRegulatorID and of an
* IntersectionID that is unique within that region. When the RoadRegulatorID is present the IntersectionReferenceID is
* guaranteed to be globally unique.
*
* @field region: a globally unique regional assignment value typical assigned to a regional DOT authority
*                the value zero shall be used for testing needs
* @field id: a unique mapping to the intersection in question within the above region of use
*
* @note: A fully qualified intersection consists of its regionally unique ID (the IntersectionID) and its region ID (the
*        RoadRegulatorID). Taken together these form a unique value which is never repeated.
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionReferenceID ::= SEQUENCE {
  region  RoadRegulatorID OPTIONAL,
  id      IntersectionID
}

/**
* This DF is used to convey all the SPAT information for a single intersection. Both current
* and future data can be sent.
*
* @field name: human readable name for intersection to be used only in debug mode
* @field id: A globally unique value set, consisting of a regionID and intersection ID assignment
*            provides a unique mapping to the intersection MAP in question which provides complete location
*            and approach/move/lane data
* @field revision: The data element **revision** is used to communicate the actual valid release of the intersection
*                  description. If there are no changes in the deployed intersection description, almost the same revision
*                  counter is transmitted. Due to a revised deployment of the intersection description (e.g. introduction of
*                  additional signal state element), the revision is increased by one. After revision equal to 127, the
*                  increment leads to 0 (due to the element range).
*                  The intersection state and the intersection geometry is related to each other. Therefore, the revision of
*                  the intersection state shall be the same as the revision of the intersection geometry (see the data
*                  element **revision** of **DF_IntersectionGeometry** in [ISO TS 19091] G.8.2.6).
* @field status: general status of the controller(s)
* @field moy: Minute of current UTC year, used only with messages to be archived.
* @field timeStamp: the mSec point in the current UTC minute that this message was constructed.
* @field enabledLanes: a list of lanes where the RevocableLane bit has been set which are now active and
*                      therefore part of the current intersection
* @field states: Each Movement is given in turn and contains its signal phase state,
*                mapping to the lanes it applies to, and point in time it will end, and it
*                may contain both active and future states
* @field maneuverAssistList: Assist data
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionState ::= SEQUENCE {
  name         DescriptiveName OPTIONAL,
  id           IntersectionReferenceID,
  revision     MsgCount,
  status       IntersectionStatusObject,
  moy          MinuteOfTheYear OPTIONAL,
  timeStamp    DSecond OPTIONAL,
  enabledLanes EnabledLaneList OPTIONAL,
  states       MovementList,
  maneuverAssistList  ManeuverAssistList OPTIONAL,
  regional     SEQUENCE (SIZE(1..4)) OF
               RegionalExtension {{Reg-IntersectionState}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of IntersectionState entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionStateList ::= SEQUENCE (SIZE(1..32)) OF  IntersectionState

/**
* This DF holds all of the constant attribute information of any lane object (as well as
* denoting the basic lane type itself) within a single structure. Constant attribute information are those values which do not
* change over the path of the lane, such as the direction of allowed travel. Other lane attribute information can change at or
* between each node.
* The structure consists of three element parts as follows: LaneDirection specifies the allowed directions of travel, if any.
* LaneSharing indicates whether this lane type is shared with other types of travel modes or users. The lane type is defined
* in LaneTypeAttributes, along with additional attributes specific to that type.
* The fundamental type of lane object is described by the element selected in the LaneTypeAttributes data concept.
* Additional information specific or unique to a given lane type can be found there as well. A regional extension is provided
* as well.
* Note that combinations of regulatory maneuver information such as "both a left turn and straight ahead movement are
* allowed, but never a u-turn," are expressed by the AllowedManeuvers data concept which typically follows after this
* element and in the same structure. Note that not all lane objects require this information (for example a median). The
* various values are set via bit flags to indicate the assertion of a value. Each defined lane type contains the bit flags
* suitable for its application area.
* Note that the concept of LaneSharing is used to indicate that there are other users of this lane with equal regulatory rights
* to occupy the lane (which is a term this standard does not formally define since it varies by world region). A typical case is
* a light rail vehicle running along the same lane path as motorized traffic. In such a case, motor traffic may be allowed
* equal access to the lane when a train is not present. Another case would be those intersection lanes (at the time of writing
* rather unusual) where bicycle traffic is given full and equal right of way to an entire width of motorized vehicle lane. This
* example would not be a bike lane or bike box in the traditional sense.
*
* @field directionalUse: directions of lane use
* @field sharedWith: co-users of the lane path
* @field laneType: specific lane type data
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes ::= SEQUENCE {
  directionalUse  LaneDirection,
  sharedWith      LaneSharing,
  laneType        LaneTypeAttributes,
  regional        RegionalExtension {{Reg-LaneAttributes}} OPTIONAL
}

/**
* This DF is used to relate an attribute and a control value at a node point or along a
* lane segment from an enumerated list of defined choices. It is then followed by a defined data value associated with it and
* which is defined elsewhere in this standard.
*
* @field pathEndPointAngle: adjusts final point/width slant of the lane to align with the stop line
* @field laneCrownPointCenter: sets the canter of the road bed from centerline point
* @field laneCrownPointLeft: sets the canter of the road bed from left edge
* @field laneCrownPointRight: sets the canter of the road bed from right edge
* @field laneAngle: the angle or direction of another lane this is required when a merge point angle is required
* @field speedLimits: Reference regulatory speed limits used by all segments
* @field regional: optional region specific data.
*
* @note: This data concept handles a variety of use case needs with a common and consistent message pattern. The
*     typical use of this data concept (and several similar others) is to inject the selected Attribute into the spatial description of
*     a lane's center line path (the segment list). In this way, attribute information which is true for a portion of the overall lane
*     can be described when needed. This attribute information applies from the node point in the stream of segment data until
*     changed again. Denoting the porous aspects of a lane along its path as it merges with another lane would be an example
*     of this use case. In this case the start and end node points would be followed by suitable segment attributes. Re-using a
*     lane path (previously called a computed lane) is another example. In this case the reference lane to be re-used appears
*     as a segment attribute followed by the lane value. It is then followed by one or more segment attributes which relate the
*     positional translation factors to be used (offset, rotate, scale) and any further segment attribute changes.
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneDataAttribute ::= CHOICE {
   pathEndPointAngle        DeltaAngle,
   laneCrownPointCenter     RoadwayCrownAngle,
   laneCrownPointLeft       RoadwayCrownAngle,
   laneCrownPointRight      RoadwayCrownAngle,
   laneAngle                MergeDivergeNodeAngle,
   speedLimits              SpeedLimitList,
   regional  SEQUENCE (SIZE(1..4)) OF
             RegionalExtension {{Reg-LaneDataAttribute}},
   ...
}

/**
* This DF consists of a list of LaneDataAttribute entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneDataAttributeList ::= SEQUENCE (SIZE(1..8)) OF LaneDataAttribute

/**
* This DF consists of a list of GenericLane entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneList ::= SEQUENCE (SIZE(1..255)) OF GenericLane

/**
* This DE is used to denote the presence of other user types (travel modes) who have an
* equal right to access and use the lane. There may also be another lane object describing their use of a lane. This data
* concept is used to indicate lanes and/or users that travel along the same path, and not those that simply cross over the
* lane's segments path (such as a pedestrian crosswalk crossing a lane for motor vehicle use). The typical use is to alert
* the user of the MAP data that additional traffic of another mode may be present in the same spatial lane.
*
* Bits used:
* - 0 - overlappingLaneDescriptionProvided: Assert when another lane object is present to describe the
*                                           path of the overlapping shared lane this construct is not used for lane objects which simply cross
* - 1 - multipleLanesTreatedAsOneLane: Assert if the lane object path and width details represents multiple lanes within it
*                                      that are not further described Various modes and type of traffic that may share this lane:
* - 2 - otherNonMotorizedTrafficTypes: horse drawn etc.
* - 3 - individualMotorizedVehicleTraffic:
* - 4 - busVehicleTraffic:
* - 5 - taxiVehicleTraffic:
* - 6 - pedestriansTraffic:
* - 7 - cyclistVehicleTraffic:
* - 8 - trackedVehicleTraffic:
* - 9 - pedestrianTraffic:
*
* @note: All zeros would indicate **not shared** and **not overlapping**
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneSharing ::= BIT STRING {
   overlappingLaneDescriptionProvided  (0),
   multipleLanesTreatedAsOneLane       (1),
   otherNonMotorizedTrafficTypes       (2),
   individualMotorizedVehicleTraffic   (3),
   busVehicleTraffic                   (4),
   taxiVehicleTraffic                  (5),
   pedestriansTraffic                  (6),
   cyclistVehicleTraffic               (7),
   trackedVehicleTraffic               (8),
   pedestrianTraffic                   (9)
} (SIZE (10))

/**
* This DF is used to hold attribute information specific to a given lane type. It is typically
* used in the DE_LaneAttributes data frame as part of an overall description of a lane object. Information unique to the
* specific type of lane is found here. Information common to lanes is expressed in other entries. The various values are set
* by bit flags to indicate the assertion of a value. Each defined lane type contains bit flags suitable for its application area.
*
* @field vehicle:         motor vehicle lanes
*
* @field crosswalk:       pedestrian crosswalks
*
* @field bikeLane:        bike lanes
*
* @field sidewalk:        pedestrian sidewalk paths
*
* @field median:          medians & channelization
*
* @field striping:        roadway markings
*
* @field trackedVehicle:  trains and trolleys
*
* @field parking:         parking and stopping lanes
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneTypeAttributes ::= CHOICE {
  vehicle        LaneAttributes-Vehicle,
  crosswalk      LaneAttributes-Crosswalk,
  bikeLane       LaneAttributes-Bike,
  sidewalk       LaneAttributes-Sidewalk,
  median         LaneAttributes-Barrier,
  striping       LaneAttributes-Striping,
  trackedVehicle LaneAttributes-TrackedVehicle,
  parking        LaneAttributes-Parking,
  ...
}

/**
* This DF consists of a list of @ref ConnectionManeuverAssist entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
ManeuverAssistList ::= SEQUENCE (SIZE(1..16)) OF ConnectionManeuverAssist

/**
* This DF contains details about a single movement. It is used by the movement state to
* convey one of number of movements (typically occurring over a sequence of times) for a SignalGroupID.
*
* @field eventState: Consisting of: Phase state (the basic 11 states), Directional, protected, or permissive state
* @field timing: Timing Data in UTC time stamps for event includes start and min/max end times of phase confidence and estimated next occurrence
* @field speeds: various speed advisories for use by general and specific types of vehicles supporting green-wave and other flow needs
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
MovementEvent ::= SEQUENCE {
  eventState   MovementPhaseState,
  timing       TimeChangeDetails OPTIONAL,
  speeds       AdvisorySpeedList OPTIONAL,
  regional     SEQUENCE (SIZE(1..4)) OF
               RegionalExtension {{Reg-MovementEvent}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of @ref MovementEvent entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
MovementEventList ::= SEQUENCE (SIZE(1..16)) OF MovementEvent

/**
* This DF consists of a list of @ref MovementState entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
MovementList ::= SEQUENCE (SIZE(1..255)) OF MovementState

/**
* This DF is used to convey various information about the current or future movement state of
* a designated collection of one or more lanes of a common type. This is referred to as the GroupID. Note that lane object
* types supported include both motorized vehicle lanes as well as pedestrian lanes and dedicated rail and transit lanes. Of
* the reported data elements, the time to change (the time remaining in the current state) is often of the most value. Lanes
* with a common state (typically adjacent sets of lanes in an approach) in a signalized intersection will have individual lane
* values such as total vehicle counts, summed. It is used in the SPAT message to convey every active movement in a
* given intersection so that vehicles, when combined with certain map information, can determine the state of the signal phases.
*
* @field movementName: uniquely defines movement by name human readable name for intersection to be used only in debug mode.
* @field signalGroup: is used to map to lists of lanes (and their descriptions) which this MovementState data applies to.
* @field state-time-speed: Consisting of sets of movement data with @ref SignalPhaseState, @ref TimeChangeDetail and @ref AdvisorySpeed
*                          *Note:* one or more of the movement events may be for a future time and that this allows conveying multiple
*                          predictive phase and movement timing for various uses for the current signal group.
* @field maneuverAssistList: This information may also be placed in the @ref IntersectionState when common information applies to different lanes in the same way
* @field regional: optional region specific data.
*
* @note: Note that the value given for the time to change will vary in many actuated signalized intersections based on
*      the sensor data received during the phase. The data transmitted always reflects the then most current timemark value
*      (which is the point in UTC time when the change will occur). As an example, in a phase which may vary from 15 to 25
*      seconds of duration based on observed traffic flows, a time to change value of 15 seconds in the future might be
*      transmitted for many consecutive seconds (and the time mark value extended for as much as 10 seconds depending on
*      the extension time logic used by the controller before it either times out or gaps out), followed by a final time mark value
*      reflecting the decreasing values as the time runs out, presuming the value was not again extended to a new time mark
*      due to other detection events. The time to change element can therefore generally be regarded as a guaranteed minimum
*      value of the time that will elapse unless a preemption event occurs.
*
*      In use, the @ref SignalGroupID element is matched to lanes that are members of that ID. The type of lane (vehicle, crosswalk,
*      etc.) is known by the lane description as well as its allowed maneuvers and any vehicle class restrictions. Every lane type
*      is treated the same way (cross walks map to suitable meanings, etc.). Lane objects which are not part of the sequence of
*      signalized lanes do not appear in any GroupID. The visual details of how a given signal phase is presented to a mobile
*      user will vary based on lane type and with regional conventions. Not all signal states will be used in all regional
*      deployments. For example, a pre-green visual indication is not generally found in US deployments. Under such operating
*      conditions, the unused phase states are simply skipped.
* @category: Infrastructure information
* @revision: V1.3.1
*/
MovementState ::= SEQUENCE {
  movementName       DescriptiveName OPTIONAL,
  signalGroup        SignalGroupID,
  state-time-speed   MovementEventList,
  maneuverAssistList ManeuverAssistList OPTIONAL,
  regional           SEQUENCE (SIZE(1..4)) OF
                     RegionalExtension {{Reg-MovementState}} OPTIONAL,
  ...
}

/**
* All the node attributes defined in this DF are valid in the direction of
* node declaration and not in driving direction (i.e. along the sequence of the declared nodes). E.g. node
* attributes of an **ingress** or an **egress** lane are defined from the conflict area (first node) to the
* outside of the intersection (last node). Node attributes with **left** and **right** in their name are also
* defined in the direction of the node declaration. This allows using attributes in a unambigious way also
* for lanes with biderctional driving. See the following attribuets examples for additianl explanations.
*
* @field localNode: Attribute states which pertain to this node point
* @field disabled: Attribute states which are disabled at this node point
* @field enabled: Attribute states which are enabled at this node point and which remain enabled until disabled or the lane ends
* @field data: Attributes which require an additional data values some of these are local to the node point, while others
*              persist with the provided values until changed and this is indicated in each entry
* @field dWidth: A value added to the current lane width at this node and from this node onwards, in 1cm steps
*               lane width between nodes are a linear taper between pts the value of zero shall not be sent here.
* @field dElevation: A value added to the current Elevation at this node from this node onwards, in 10cm steps
*                    elevations between nodes are a linear taper between pts the value of zero shall not be sent here
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
NodeAttributeSetXY ::= SEQUENCE {
  localNode    NodeAttributeXYList OPTIONAL,
  disabled     SegmentAttributeXYList OPTIONAL,
  enabled      SegmentAttributeXYList OPTIONAL,
  data         LaneDataAttributeList OPTIONAL,
  dWidth       Offset-B10 OPTIONAL,
  dElevation   Offset-B10 OPTIONAL,
  regional     SEQUENCE (SIZE(1..4)) OF
               RegionalExtension {{Reg-NodeAttributeSetXY}} OPTIONAL,
  ...
}

/**
* This DE is an enumerated list of attributes which can pertain to the current node
* point. The **scope** of these values is limited to the node itself. That is, unlike other types of attributes which can be
* switched on or off at any given node (and hence pertains to one or more segments), the DE_NodeAttribute is local to the
* node in which it is found. These attributes are all binary flags in that they do not need to convey any additional data. Other
* attributes allow sending short data values to reflect a setting which is set and persists in a similar fashion.
*
*  - reserved:             do not use
*  - stopLine:             point where a mid-path stop line exists. See also **do not block** for segments
*  - roundedCapStyleA:     Used to control final path rounded end shape with edge of curve at final point in a circle
*  - roundedCapStyleB:     Used to control final path rounded end shape with edge of curve extending 50% of width past final point in a circle
*  - mergePoint:           merge with 1 or more lanes
*  - divergePoint:         diverge with 1 or more lanes
*  - downstreamStopLine:   downstream intersection (a 2nd intersection) stop line
*  - downstreamStartNode:  downstream intersection (a 2nd intersection) start node
*  - closedToTraffic:      where a pedestrian may NOT go to be used during construction events
*  - safeIsland:           a pedestrian safe stopping point also called a traffic island
*                          This usage described a point feature on a path, other entries can describe a path
*  - curbPresentAtStepOff: the sidewalk to street curb is NOT angled where it meets the edge of the roadway (user must step up/down)
*  - hydrantPresent:       Or other services access
*
* @note: See usage examples in [ISO TS 19091] G.8.2.8
* @category: Infrastructure information
* @revision: V1.3.1
*/
NodeAttributeXY ::= ENUMERATED {
  reserved,
  stopLine,
  roundedCapStyleA,
  roundedCapStyleB,
  mergePoint,
  divergePoint,
  downstreamStopLine,
  downstreamStartNode,
  closedToTraffic,
  safeIsland,
  curbPresentAtStepOff,
  hydrantPresent,
  ...
}

/**
* This DF consists of a list of @ref NodeAttributeXY entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
NodeAttributeXYList ::= SEQUENCE (SIZE(1..8)) OF NodeAttributeXY

/**
* A 64-bit node type with lat-long values expressed in one tenth of a micro degree.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Node-LLmD-64b ::= SEQUENCE {
  lon  Longitude,
  lat  Latitude
}

/**
* A 20-bit node type with offset values from the last point in X and Y.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Node-XY-20b ::= SEQUENCE {
  x  Offset-B10,
  y  Offset-B10
}

/**
* A 22-bit node type with offset values from the last point in X and Y.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Node-XY-22b ::= SEQUENCE {
  x  Offset-B11,
  y  Offset-B11
}

/**
* A 24-bit node type with offset values from the last point in X and Y.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Node-XY-24b ::= SEQUENCE {
  x  Offset-B12,
  y  Offset-B12
}

/**
* A 26-bit node type with offset values from the last point in X and Y.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Node-XY-26b ::= SEQUENCE {
  x  Offset-B13,
  y  Offset-B13
}

/**
* A 28-bit node type with offset values from the last point in X and Y.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Node-XY-28b ::= SEQUENCE {
  x  Offset-B14,
  y  Offset-B14
}

/**
* A 32-bit node type with offset values from the last point in X and Y.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Node-XY-32b ::= SEQUENCE {
  x  Offset-B16,
  y  Offset-B16
}

/**
* This DF provides the sequence of signed offset node point values for determining the Xs and Ys
* (and possibly Width or Zs when present), using the then current Position3D object to build a path for the centerline of
* the subject lane type. Each X,Y point is referred to as a Node Point. The straight line paths between these points are
* referred to as Segments.
* All nodes may have various optional attributes the state of which can vary along the path and which are enabled and
* disabled by the sequence of objects found in the list of node structures. Refer to the explanatory text in Section 11 for a
* description of how to correctly encode and decode this type of the data element. As a simple example, a motor vehicle
* lane may have a section of the overall lane path marked "do not block", indicating that vehicles should not come to a stop
* and remain in that region. This is encoded in the Node data structures by an element in one node to indicate the start of
* the "do not block" lane attributes at a given offset, and then by a termination element when this attribute is set false. Other
* types of elements in the segment choice allow inserting attributes containing data values affecting the segment or the
* node.
*
* @field nodes: a lane made up of two or more XY node points and any attributes defined in those nodes
* @field computed: a lane path computed by translating the data defined by another lane
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
NodeListXY ::= CHOICE {
  nodes     NodeSetXY,
  computed  ComputedLane,
  ...
}

/**
* This DF presents a structure to hold different sized data frames for a single node
* point in a lane. Nodes are described in terms of X and Y offsets in units of 1 centimeter (when zoom is 1:1). Changes in
* elevation and in the lane width can be expressed in a similar way with the optional Attributes data entry which appears
* alongside the NodeOffsetPoint in use.
*
* The choice of which node type is driven by the magnitude (size) of the offset data to be encoded. When the distance from
* the last node point is smaller, the smaller entries can (and should) be chosen
* Each single selected node is computed as an X and Y offset from the prior node point unless one of the entries reflecting
* a complete lat-long representation is selected. In this case, subsequent entries become offsets from that point. This ability
* was added for assistance with the development, storage, and back office exchange of messages where message size is
* not a concern and should not be sent over the air due to its additional message payload size.
*
* The general usage guidance is to construct the content of each lane node point with the smallest possible element to
* conserve message size. However, using an element which is larger than needed is not a violation of the ASN.1 rules.
*
* @field node-XY1:    node is within 5.11m of last node
* @field node-XY2:    node is within 10.23m of last node
* @field node-XY3:    node is within 20.47m of last node
* @field node-XY4:    node is within 40.96m of last node
* @field node-XY5:    node is within 81.91m of last node
* @field node-XY6:    node is within 327.67m of last node
* @field node-LatLon: node is a full 32b Lat/Lon range
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
NodeOffsetPointXY ::= CHOICE {
  node-XY1         Node-XY-20b,
  node-XY2         Node-XY-22b,
  node-XY3         Node-XY-24b,
  node-XY4         Node-XY-26b,
  node-XY5         Node-XY-28b,
  node-XY6         Node-XY-32b,
  node-LatLon      Node-LLmD-64b,
  regional         RegionalExtension {{Reg-NodeOffsetPointXY}}
}

/**
* This DF presents a structure to hold data for a single node point in a path. Each selected node
* has an X and Y offset from the prior node point (or a complete lat-long representation in some cases) as well as optional
* attribute information. The node list for a lane (or other object) is made up of a sequence of these to describe the desired
* path. The X,Y points are selected to reflect the centerline of the path with sufficient accuracy for the intended applications.
* Simple lanes can be adequately described with only two node points, while lanes with curvature may require more points.
* Changes to the lane width and elevation can be expressed in the NodeAttributes entry, as well as various attributes that
* pertain to either the current node point or to one of more subsequent segments along the list of lane node points. As a
* broad concept, NodeAttributes are used to describe aspects of the lane that persist for only a portion of the overall lane
* path (either at a node or over a set of segments).
* A further description of the use of the NodeOffsetPoint and the Attributes data concepts can be found in the data
* dictionary entries for each one. Note that each allows regional variants to be supported as well.
*
* @field delta:      A choice of which X,Y offset value to use this includes various delta values as well a regional choices.
* @field attributes: Any optional Attributes which are needed. This includes changes to the current lane width and elevation.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
NodeXY ::= SEQUENCE {
  delta       NodeOffsetPointXY,
  attributes  NodeAttributeSetXY OPTIONAL,
  ...
}

/**
* This DF consists of a list of Node entries using XY offsets.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
NodeSetXY ::= SEQUENCE (SIZE(2..63)) OF NodeXY

/** This DF is the ODG Addition for Legancy R09 telegrams.
* 
* @field reportingPoint: reporting point as of R09 (maps to R09 field M Meldepunktnummer)
* @field priorityLevel:  priority level as of R09 (maps to R09 field P Prioritaet)
* @field length:         train length point as of R09 (maps to R09 field A Zuglaenge)
* @field route:          route as of R09 (maps to R09 field K Kursnummer)
* @field line:           line as of R09 (maps to R09 field L Liniennummer)
* @field direction:      direction as of R09 (maps to R09 field H Richtung von Hand)
* @field tour:           tour as of R09 (maps to R09 field Z Zielnummer)
* @field version:        version of R09
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
OcitRequestorDescriptionContainer ::= SEQUENCE {
  reportingPoint      ReportingPoint OPTIONAL,
  priorityLevel       PriorityLevel OPTIONAL,
  length              TrainLength OPTIONAL,
  route               RouteNumber OPTIONAL,
  line                LineNumber OPTIONAL,
  direction           TransitDirection OPTIONAL,
  tour                TourNumber OPTIONAL,
  version             VersionId OPTIONAL,
  ...
}

/**
* This DF is a sequence of lane IDs which refers to lane objects that overlap or overlay the current lane's spatial path.
*
* Contains the unique ID numbers for any lane object which have spatial paths that overlay (run on top of, and not
* simply cross with) the current lane.
* Such as a train path that overlays a motor vehicle lane object for a roadway segment.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
OverlayLaneList ::= SEQUENCE (SIZE(1..5)) OF LaneID

/**
* This DF consists of various parameters of quality used to model the accuracy of the
* positional determination with respect to each given axis.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
PositionalAccuracy ::= SEQUENCE {
   semiMajor     SemiMajorAxisAccuracy,
   semiMinor     SemiMinorAxisAccuracy,
   orientation   SemiMajorAxisOrientation
}

/**
* This DF combines multiple related bit fields into a single concept.
*
* @field pos:       confidence for both horizontal directions
* @field elevation: confidence for vertical direction
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
PositionConfidenceSet ::= SEQUENCE {
   pos        PositionConfidence,
   elevation  ElevationConfidence
}

/**
* This DF provides a precise location in the WGS-84 coordinate system, from which short
* offsets may be used to create additional data using a flat earth projection centered on this location. Position3D is typically
* used in the description of maps and intersections, as well as signs and traveler data.
*
* @field lat: Latitude in 1/10th microdegrees
* @field long: Longitude in 1/10th microdegrees
* @field elevation: The elevation information is defined by the regional extension (see module ETSI-ITS-DSRC-AddGrpC). 
*                   Therefore, the **elevation** data element of **DF_Position3D** is not used.
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Position3D ::= SEQUENCE {
  lat        Latitude,
  long       Longitude,
  elevation  Elevation  OPTIONAL,
  regional   SEQUENCE (SIZE(1..4)) OF
             RegionalExtension {{Reg-Position3D}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of RegionalSignalControlZone entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
PreemptPriorityList ::= SEQUENCE (SIZE(1..32)) OF SignalControlZone

/**
* This DF is used to convey a regulatory speed about a lane, lanes, or roadway segment.
*
* @field type: The type of regulatory speed which follows
* @field speed: The speed in units of 0.02 m/s
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RegulatorySpeedLimit ::= SEQUENCE {
  type        SpeedLimitType,
  speed       Velocity
}

/**
* This DF is used to provide identity information about a selected vehicle or users.
* This data frame is typically used with fleet type vehicles which can (or which must) safely release such information for use
* with probe measurements or with other interactions (such as a signal request).
*
* @field id:               The ID used in the CAM of the requestor. This ID is presumed not to change during the exchange.
* @field type:             Information regarding all type and class data about the requesting vehicle
* @field position:         The location of the requesting vehicle
* @field name:             A human readable name for debugging use
* @field routeName:        A string for transit operations use
* @field transitStatus:    current vehicle state (loading, etc.)
* @field transitOccupancy: current vehicle occupancy
* @field transitSchedule:  current vehicle schedule adherence
* @field regional:         optional region specific data.
* @field ocit:             Extension container for Legacy R09 data (as defined by [OCIT]).
*
* @note: Note that the requestor description elements which are used when the request (the req) is made differ from
*        those used when the status of an active or pending request is reported (the ack). Typically, when reporting the status to
*        other parties, less information is required and only the temporaryID (contained in the VehicleID) and request number (a
*        unique ID used in the orginal request) are used.
* @category: Infrastructure information
* @revision: V1.3.1
*/
RequestorDescription ::= SEQUENCE {
  id                VehicleID,
  type              RequestorType OPTIONAL,
  position          RequestorPositionVector OPTIONAL,
  name              DescriptiveName OPTIONAL,
  routeName         DescriptiveName OPTIONAL,
  transitStatus     TransitVehicleStatus OPTIONAL,
  transitOccupancy  TransitVehicleOccupancy OPTIONAL,
  transitSchedule   DeltaTime OPTIONAL,
  regional          SEQUENCE (SIZE(1..4)) OF RegionalExtension {{Reg-RequestorDescription}} OPTIONAL,
  ...,
  ocit OcitRequestorDescriptionContainer -- Extension for OCIT in V2.2.1
}

/**
* This DF provides a report of the requestor's position, speed, and heading.
* Used by a vehicle or other type of user to request services and at other times when the larger FullPositionVector is not required.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RequestorPositionVector ::= SEQUENCE {
  position           Position3D,
  heading            Angle OPTIONAL,
  speed              TransmissionAndSpeed OPTIONAL,
  ...
}

/**
* This DF is used when a DSRC-equipped device is requesting service from another
* device. The most common use case is when a vehicle is requesting a signal preemption or priority service call from the
* signal controller in an intersection. This data frame provides the details of the requestor class taxonomy required to
* support the request. Depending on the precise use case and the local implementation, these details can vary
* considerably. As a result, besides the basic role of the vehicle, the other classification systems supported are optional. It
* should also be observed that often only a subset of the information in the RequestorType data frame is used to report the
* "results" of such a request to others. As an example, a police vehicle might request service based on being in a police
* vehicle role (and any further sub-type if required) and on the type of service call to which the vehicle is then responding
* (perhaps a greater degree of emergency than another type of call), placing these information elements in the
* RequestorType, which is then part of the Signal Request Message (SRM). This allows the roadway operator to define
* suitable business rules regarding how to reply. When informing the requestor and other nearby drivers of the outcome,
* using the Signal Status Message (SSM) message, only the fact that the preemption was granted or denied to some
* vehicle with a unique request ID is conveyed.
*
* @field role:     Basic role of this user at this time.
* @field subrole:  A local list with role based items.
* @field request:  A local list with request items
* @field iso3883:  Additional classification details
* @field hpmsType: HPMS classification types
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RequestorType ::= SEQUENCE {
  role         BasicVehicleRole,
  subrole      RequestSubRole OPTIONAL,
  request      RequestImportanceLevel OPTIONAL,
  iso3883      Iso3833VehicleType OPTIONAL,
  hpmsType     VehicleType OPTIONAL,
  regional     RegionalExtension {{Reg-RequestorType}} OPTIONAL,
  ...
}

/**
* This DF is used to assign (or bind) a single RestrictionClassID data
* element to a list of all user classes to which it applies. A collection of these bindings is conveyed in the
* RestrictionClassList data frame in the MAP message to travelers. The established index is then used in the lane object of
* the MAP message, in the ConnectTo data frame, to qualify to whom a signal group ID applies when it is sent by the SPAT
* message about a movement.
*
* @field id: the unique value (within an intersection or local region) that is assigned to this group of users.
* @field users: The list of user types/classes to which this restriction ID applies.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RestrictionClassAssignment ::= SEQUENCE {
  id       RestrictionClassID,
  users    RestrictionUserTypeList
}

/**
* This DF is used to enumerate a list of user classes which belong to a given
* assigned index. The resulting collection is treated as a group by the signal controller when it issues movement data
* (signal phase information) with the GroupID for this group. This data frame is typically static for long periods of time
* (months) and conveyed to the user by means of the MAP message.
*
* @note: The overall restriction class assignment process allows dynamic support within the framework of the common
*        message set for the various special cases that some signalized intersections must support. While the assigned value
*        needs to be unique only within the scope of the intersection that uses it, the resulting assignment lists will tend to be static
*        and stable for regional deployment areas such as a metropolitan area based on their operational practices and needs.
* @category: Infrastructure information
* @revision: V1.3.1
*/
RestrictionClassList ::= SEQUENCE (SIZE(1..254)) OF RestrictionClassAssignment

/**
* This DF is used to provide a means to select one, and only one, user type or class
* from a number of well-known lists. The selected entry is then used in the overall Restriction Class assignment process to
* indicate that a given GroupID (a way of expressing a movement in the SPAT/MAP system) applies to (is restricted to) this
* class of user.
*
* @field basicType: a set of the most commonly used types.
* @field regional:  optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RestrictionUserType ::= CHOICE {
  basicType   RestrictionAppliesTo,
  regional    SEQUENCE (SIZE(1..4)) OF
              RegionalExtension {{Reg-RestrictionUserType}},
  ...
}

/**
* This DF consists of a list of @ref RestrictionUserType entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RestrictionUserTypeList ::= SEQUENCE (SIZE(1..16)) OF  RestrictionUserType

/**
* This DF consists of a list of GenericLane entries used to describe a segment of roadway.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RoadLaneSetList ::= SEQUENCE (SIZE(1..255)) OF GenericLane

/**
* This DF is used to convey theRoadSegmentID which is unique to a given road segment of interest,
* and also the RoadRegulatorID assigned to the region in which it is operating (when required).
*
* @field region: a globally unique regional assignment value typically assigned to a regional DOT authority the value zero shall be used for testing needs.
* @field id:     a unique mapping to the road segment in question within the above region of use during its period of assignment and use
*                note that unlike intersectionID values, this value can be reused by the region.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RoadSegmentReferenceID ::= SEQUENCE {
  region  RoadRegulatorID OPTIONAL,
  id      RoadSegmentID
}

/**
* This DF is a complete description of a RoadSegment including its geometry and its
* allowed navigational paths (independent of any additional regulatory restrictions that may apply over time or from user
* classification) and any current disruptions such as a work zone or incident event.
*
* @field name: some descriptive text.
* @field id: a globally unique value for the segment.
* @field revision: .
* @field refPoint: the reference from which subsequent data points are offset until a new point is used.
* @field laneWidth: Reference width used by all subsequent lanes unless a new width is given.
* @field speedLimits: Reference regulatory speed limits used by all subsequent lanes unless a new speed is given.
* @field roadLaneSet: Data describing disruptions in the RoadSegment such as work zones etc will be added here.
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RoadSegment ::= SEQUENCE {
  name        DescriptiveName OPTIONAL,
  id          RoadSegmentReferenceID,
  revision    MsgCount,
  refPoint    Position3D,
  laneWidth   LaneWidth OPTIONAL,
  speedLimits SpeedLimitList OPTIONAL,
  roadLaneSet RoadLaneSetList,
  regional    SEQUENCE (SIZE(1..4)) OF
              RegionalExtension {{Reg-RoadSegment}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of @ref RoadSegment entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RoadSegmentList ::= SEQUENCE (SIZE(1..32)) OF RoadSegment

/**
* This DF is a collection of data values used to convey RTCM information between users. It
* is not required or used when sending RTCM data from a corrections source to end users (from a base station to devices
* deployed in the field which are called rovers).
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RTCMheader ::= SEQUENCE {
   status     GNSSstatus,
   offsetSet  AntennaOffsetSet
}

/**
* This DF consists of a list of @ref RTCMmessage entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RTCMmessageList ::= SEQUENCE (SIZE(1..5)) OF RTCMmessage

/**
* This DF consists of a list of @ref SegmentAttributeXY entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SegmentAttributeXYList ::= SEQUENCE (SIZE(1..8)) OF SegmentAttributeXY

/**
* This DF is a dummy placeholder to contain a regional SignalControlZone DF.
* It is not used, yet here for backwards compatibility.
*
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalControlZone ::=  SEQUENCE {
  zone  RegionalExtension {{Reg-SignalControlZone}},
  ...
}

/**
* This DF is used to contain information regarding the entity that requested a given
* signal behavior. In addition to the VehicleID, the data frame also contains a request reference number used to uniquely
* refer to the request and some basic type information about the request maker which may be used by other parties.
*
* @field id: to uniquely identify the requester and the specific request to all parties.
* @field request: to uniquely identify the requester and the specific request to all parties.
* @field sequenceNumber: to uniquely identify the requester and the specific request to all parties.
* @field role: vehicle role
* @field typeData: Used when addition data besides the role is needed, at which point the role entry above is not sent.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalRequesterInfo ::= SEQUENCE {
  id             VehicleID,
  request        RequestID,
  sequenceNumber MsgCount,
  role           BasicVehicleRole OPTIONAL,
  typeData       RequestorType OPTIONAL,
  ...
}

/**
* This DF is used (as part of a request message) to request either a priority or a preemption service
* from a signalized intersection. It relates the intersection ID as well as the specific request information. Additional
* information includes the approach and egress values or lanes to be used.
*
* @field id: the unique ID of the target intersection
* @field requestID: The unique requestID used by the requestor
* @field requestType: The type of request or cancel for priority or preempt use when a prior request is canceled, only the requestID is needed.
* @field inBoundLane: desired entry approach or lane.
* @field outBoundLane: desired exit approach or lane. the value zero is used to indicate intent to stop within the intersection.
* @field regional: optional region specific data.
*
* @note: In typical use either an approach or a lane number would be given, this indicates the requested
*        path through the intersection to the degree it is known.
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalRequest ::= SEQUENCE {
  id            IntersectionReferenceID,
  requestID     RequestID,
  requestType   PriorityRequestType,
  inBoundLane   IntersectionAccessPoint,
  outBoundLane  IntersectionAccessPoint OPTIONAL,
  regional      SEQUENCE (SIZE(1..4)) OF
                RegionalExtension {{Reg-SignalRequest}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of @ref SignalRequest entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalRequestList ::= SEQUENCE (SIZE(1..32)) OF SignalRequestPackage

/**
* This DF contains both the service request itself (the preemption and priority
* details and the inbound-outbound path details for an intersection) and the time period (start and end time) over which this
* service is sought from one single intersection. One or more of these packages are contained in a list in the Signal
* Request Message (SREM).
*
* @field request:  The specific request to the intersection contains IntersectionID, request type, requested action (approach/lane request).
* @field minute:   Time period start.
* @field second:   Time period start.
* @field duration: The duration value is used to provide a short interval that extends the ETA so that the requesting vehicle can arrive at
*                  the point of service with uncertainty or with some desired duration of service. This concept can be used to avoid needing
*                  to frequently update the request. The requester must update the ETA and duration values if the
*                  period of services extends beyond the duration time. It should be assumed that if the vehicle does not clear the
*                  intersection when the duration is reached, the request will be cancelled and the intersection will revert to normal operation.
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalRequestPackage ::= SEQUENCE {
  request        SignalRequest,
  minute         MinuteOfTheYear OPTIONAL,
  second         DSecond OPTIONAL,
  duration       DSecond OPTIONAL,
  regional       SEQUENCE (SIZE(1..4)) OF
                 RegionalExtension {{Reg-SignalRequestPackage}} OPTIONAL,
  ...
}

/**
* This DF is used to provide the status of a single intersection to others, including any active
* preemption or priority state in effect.
*
* @field sequenceNumber: changed whenever the below contents have change
* @field id:             this provides a unique mapping to the intersection map in question which provides complete location
*                        and approach/movement/lane data as well as zones for priority/preemption.
* @field sigStatus:      a list of detailed status containing all priority or preemption state data, both active and pending,
*                        and who requested it requests which are denied are also listed here for a short period of time.
* @field regional: optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalStatus ::= SEQUENCE {
  sequenceNumber MsgCount,
  id             IntersectionReferenceID,
  sigStatus      SignalStatusPackageList,
  regional       SEQUENCE (SIZE(1..4)) OF
                 RegionalExtension {{Reg-SignalStatus}} OPTIONAL,
  ...
}

/**
* This DF consists of a list of @ref SignalStatus entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalStatusList ::= SEQUENCE (SIZE(1..32)) OF SignalStatus

/**
* This DF consists of a list of @ref SignalStatusPackage entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalStatusPackageList ::= SEQUENCE (SIZE(1..32)) OF SignalStatusPackage

/**
* This DF contains all the data needed to describe the preemption or priority state
* of the signal controller with respect to a given request and to uniquely identify the party who requested that state to occur.
* It should be noted that this data frame describes both active and anticipated states of the controller. A requested service
* may not be active when the message is created and issued. A requested service may be rejected. This structure allows
* the description of pending requests that have been granted (accepted rather than rejected) but are not yet active and
* being serviced. It also provides for the description of rejected requests so that the initial message is acknowledged
* (completing a dialog using the broadcast messages).
*
* @field requester:  The party that made the initial SREM request.
* @field inboundOn:  estimated lane / approach of vehicle.
* @field outboundOn: estimated lane / approach of vehicle.
* @field minute:     The Estimated Time of Arrival (ETA) when the service is requested. This data echos the data of the request.
* @field second:     seconds part of ETA.
* @field duration:   duration part of ETA.
* @field status:     Status of request, this may include rejection.
* @field regional:   optional region specific data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalStatusPackage ::= SEQUENCE {
  requester    SignalRequesterInfo OPTIONAL,
  inboundOn    IntersectionAccessPoint,
  outboundOn   IntersectionAccessPoint OPTIONAL,
  minute       MinuteOfTheYear OPTIONAL,
  second       DSecond OPTIONAL,
  duration     DSecond OPTIONAL,
  status       PrioritizationResponseStatus,
  regional     SEQUENCE (SIZE(1..4)) OF
               RegionalExtension {{Reg-SignalStatusPackage}} OPTIONAL,
  ...
}

/**
* This DF is a single data frame combining multiple related bit fields into one concept.
*
* @field heading: confidence for heading values
* @field speed: confidence for speed values
* @field throttle: confidence for throttle values 
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SpeedandHeadingandThrottleConfidence ::= SEQUENCE {
   heading   HeadingConfidenceDSRC,
   speed     SpeedConfidenceDSRC,
   throttle  ThrottleConfidence
}

/**
* This DF consists of a list of SpeedLimit entries.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SpeedLimitList ::= SEQUENCE (SIZE(1..9)) OF RegulatorySpeedLimit

/**
* This DE relates the type of speed limit to which a given speed refers.
*
* - unknown: Speed limit type not available
* - maxSpeedInSchoolZone: Only sent when the limit is active
* - maxSpeedInSchoolZoneWhenChildrenArePresent: Sent at any time
* - maxSpeedInConstructionZone: Used for work zones, incident zones, etc. where a reduced speed is present
* - vehicleMinSpeed: Regulatory speed limit for general traffic
* - vehicleMaxSpeed: Regulatory speed limit for general traffic
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SpeedLimitType ::= ENUMERATED {
   unknown,
   maxSpeedInSchoolZone,
   maxSpeedInSchoolZoneWhenChildrenArePresent,
   maxSpeedInConstructionZone,
   vehicleMinSpeed,
   vehicleMaxSpeed,
   vehicleNightMaxSpeed,
   truckMinSpeed,
   truckMaxSpeed,
   truckNightMaxSpeed,
   vehiclesWithTrailersMinSpeed,
   vehiclesWithTrailersMaxSpeed,
   vehiclesWithTrailersNightMaxSpeed,
   ...
}

/**
* This DF conveys details about the timing of a phase within a movement. The core
* data concept expressed is the time stamp (time mark) at which the related phase will change to the next state. This is
* often found in the MinEndTime element, but the other elements may be needed to convey the full concept when adaptive
* timing is employed.
*
* @field startTime: is used to relate when the phase itself started or is expected to start. This in turn allows the
*                   indication that a set of time change details refers to a future phase, rather than a currently active phase.
*                   By this method, timing information about "pre" phase events (which are the short transitional phase used to alert OBUs to
*                   an impending green/go or yellow/caution phase) and the longer yellow-caution phase data is supported in the same form
*                   as various green/go phases. In theory, the time change details could be sent for a large sequence of phases if the signal
*                   timing was not adaptive and the operator wished to do so. In practice, it is expected only the "next" future phase will
*                   commonly be sent. It should be noted that this also supports the sending of time periods regarding various red phases;
*                   however, this is not expected to be done commonly.
* @field minEndTime: is used to convey the earliest time possible at which the phase could change, except when
*                   unpredictable events relating to a preemption or priority call disrupt a currently active timing plan. In a phase where the
*                   time is fixed (as in a fixed yellow or clearance time), this element shall be used alone. This value can be viewed as the
*                   earliest possible time at which the phase could change, except when unpredictable events relating to a preemption or
*                   priority call come into play and disrupt a currently active timing plan.
* @field maxEndTime: is used to convey the latest time possible which the phase could change,
*                   except when unpredictable events relating to a preemption or priority
*                   call come into play and disrupt a currently active timing plan. In a phase where the time is fixed (as in a fixed yellow or
*                   clearance time), this element shall be used alone.
* @field likelyTime: is used to convey the most likely time the phase changes. This occurs between MinEndTime and
*                   MaxEndTime and is only relevant for traffic-actuated control programs. This time might be calculated out of logged
*                   historical values, detected events (e.g., from inductive loops), or from other sources.
* @field confidence: is used to convey basic confidence data about the likelyTime.
* @field nextTime:   is used to express a general (and presumably less precise) value regarding when this phase will
*                   next occur. This is intended to be used to alert the OBU when the next green/go may occur so that various ECO driving
*                   applications can better manage the vehicle during the intervening stopped time.
*
* @note: Remarks: It should be noted that all times are expressed as absolute values and not as countdown timer values. When
*          the stated time mark is reached, the state changes to the next state. Several technical reasons led to this choice; among
*          these was that with a countdown embodiment, there is an inherent need to update the remaining time every time a SPAT
*          message is issued. This would require re-formulating the message content as as well as cryptographically signing the
*          message each time. With the use of absolute values (time marks) chosen here, the current count down time when the
*          message is created is added to the then-current time to create an absolute value and can be used thereafter without
*          change. The message content need only change when the signal controller makes a timing decision to be published. This
*          allows a clean separation of the logical functions of message creation from the logical functions of message scheduling
*          and sending, and fulfills the need to minimize further real time processing when possible. This Standard sets no limits on
*          where each of these functions is performed in the overall roadside system.
* @category: Infrastructure information
* @revision: V1.3.1
*/
TimeChangeDetails ::= SEQUENCE {
  startTime   TimeMark               OPTIONAL,
  minEndTime  TimeMark,
  maxEndTime  TimeMark               OPTIONAL,
  likelyTime  TimeMark               OPTIONAL,
  confidence  TimeIntervalConfidence OPTIONAL,
  nextTime    TimeMark               OPTIONAL
}

/**
* This DE is used to relate a moment in UTC (Coordinated Universal Time)-based time when a
* signal phase is predicted to change, with a precision of 1/10 of a second. A range of 60 full minutes is supported and it
* can be presumed that the receiver shares a common sense of time with the sender which is kept aligned to within a
* fraction of a second or better.
*
* If there is a need to send a value greater than the range allowed by the data element (over one hour in the future), the
* value 36000 shall be sent and shall be interpreted to indicate an indefinite future time value. When the value to be used is
* undefined or unknown a value of 36001 shall be sent. Note that leap seconds are also supported.
*
* The value is tenths of a second in the current or next hour in units of 1/10th second from UTC time
* - A range of 0-36000 covers one hour
* - The values 35991..35999 are used when a leap second occurs
* - The value 36000 is used to indicate time >3600 seconds
* - 36001 is to be used when value undefined or unknown
*
* @note: Note that this is NOT expressed in GPS time or in local time
* @category: Infrastructure information
* @revision: V1.3.1
*/
TimeMark ::= INTEGER (0..36001)

/**
* This DF expresses the speed of the vehicle and the state of the transmission.
* The transmission state of **reverse** can be used as a sign value for the speed element when needed.
*
* @field transmisson: state of the transmission
* @field speed: speed of the vehicle
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
TransmissionAndSpeed ::= SEQUENCE {
  transmisson   TransmissionState,
  speed         Velocity
}

/**
* This DF is used to contain either a (US) TemporaryID or an (EU) StationID in a simple frame.
* These two different value domains are used to uniquely identify a vehicle or other object in these two regional DSRC
* value is unavailable but needed by another type of user (such as the roadside infrastructure sending data about an
* environments. In normal use cases, this value changes over time to prevent tracking of the subject vehicle. When this
* unequipped vehicle), the value zero shall be used. A typical restriction on the use of this value during a dialog or other
* exchange is that the value remains constant for the duration of that exchange. Refer to the performance requirements for
* a given application for details.
*
* @field entityID: representation for US stations
* @field stationID: representation for EU stations
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
VehicleID ::= CHOICE {
  entityID     TemporaryID,
  stationID    StationID
}

/**
* This DE relates the type of travel to which a given speed refers. This element is
* typically used as part of an @ref AdvisorySpeed data frame for signal phase and timing data.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
AdvisorySpeedType ::= ENUMERATED {
  none       (0),
  greenwave  (1),
  ecoDrive   (2),
  transit    (3),
  ...
}

/**
* This DE relates the allowed (possible) maneuvers from a lane, typically a
* motorized vehicle lane. It should be noted that in practice these values may be further restricted by vehicle class, local
* regulatory environment and other changing conditions.
*
* @note: When used by data frames, the AllowedManeuvers data concept is used in two places: optionally in the
*    generic lane structure to list all possible maneuvers (as in what that lane can do at its stop line point); and within each
*    ConnectsTo structure. Each ConnectsTo structure contains a list used to provide a single valid maneuver in the context of
*    one lane connecting to another in the context of a signal phase that applies to that maneuver. It should be noted that, in
*    some intersections, multiple outbound lanes can be reached by the same maneuver (for example two independent left
*    turns might be found in a 5-legged intersection) but that to reach any given lane from the stop line of another lane is
*    always a single maneuver item (hence the use of a list). Not all intersection descriptions may contain an exhaustive set of
*    ConnectsTo information (unsignalized intersections for example) and in such cases the AllowedManeuvers in the generic
*    lane structure can be used. If present in both places, the data expressed in the generic lane shall not conflict with the data
*    found in the collection of ConnectsTo entries.
* @category: Infrastructure information
* @revision: V1.3.1
*/
AllowedManeuvers ::= BIT STRING {
  maneuverStraightAllowed      (0),
  maneuverLeftAllowed          (1),
  maneuverRightAllowed         (2),
  maneuverUTurnAllowed         (3),
  maneuverLeftTurnOnRedAllowed (4),
  maneuverRightTurnOnRedAllowed (5),
  maneuverLaneChangeAllowed    (6),
  maneuverNoStoppingAllowed    (7),
  yieldAllwaysRequired         (8),
  goWithHalt                   (9),
  caution                      (10),
  reserved1                    (11)
} (SIZE(12))

/**
* This DE is used to describe an angular measurement in units of degrees. This data
* element is often used as a heading direction when in motion. In this use, the current heading of the sending device is
* expressed in unsigned units of 0.0125 degrees from North, such that 28799 such degrees represent 359.9875 degrees.
* North shall be defined as the axis defined by the WGS-84 coordinate system and its reference ellipsoid. Any angle "to the
* east" is defined as the positive direction. A value of 28800 shall be used when Angle is unavailable.
*
* @note: Note that other heading and angle data elements of various sizes and precisions are found in other parts of this standard and in ITS.
* @unit: 0.0125 degrees
* @category: Infrastructure information
* @revision: V1.3.1
*/
Angle ::= INTEGER (0..28800)

/**
* This DE is used to relate the index of an approach, either ingress or egress within the
* subject lane. In general, an approach index in the context of a timing movement is not of value in the MAP and SPAT
* process because the lane ID and signal group ID concepts handle this with more precision. This value can also be useful
* as an aid as it can be used to indicate the gross position of a moving object (vehicle) when its lane level accuracy is
* unknown. This value can also be used when a deployment represents sets of lanes as groups without further details (as is
* done in Japan).
*
* @note: zero to be used when valid value is unknown
* @category: Infrastructure information
* @revision: V1.3.1
*/
ApproachID ::= INTEGER (0..15)

/**
* This DE provides a means to indicate the current role that a DSRC device is playing
* This is most commonly employed when a vehicle needs to take on another role in order to send certain DSRC message
* types. As an example, when a public safety vehicle such as a police car wishes to send a signal request message (SRM)
* to an intersection to request a preemption service, the vehicle takes on the role "police" from the below list in both the
* SRM message itself and also in the type of security CERT which is sent (the SSP in the CERT it used to identify the
* requester as being of type "police" and that they are allowed to send this message in this way). The BasicVehicleRole
* entry is often used and combined with other information about the requester as well, such as details of why the request is
* being made.
*
* - 0 - `basicVehicle`     - Light duty passenger vehicle type
* - 1 - `publicTransport`  - Used in EU for Transit us
* - 2 - `specialTransport` - Used in EU (e.g. heavy load)
* - 3 - `dangerousGoods`   - Used in EU for any HAZMAT
* - 4 - `roadWork`         - Used in EU for State and Local DOT uses
* - 5 - `roadRescue`       - Used in EU and in the US to include tow trucks.
* - 6 - `emergency`        - Used in EU for Police, Fire and Ambulance units
* - 7 - `safetyCar`        - Used in EU for Escort vehicles
* - 8 - `none-unknown`     - added to follow current SAE style guidelines
* - 9 - `truck`            - Heavy trucks with additional BSM rights and obligations
* - 10 - `motorcycle`      - Motorcycle
* - 11 - `roadSideSource`  - For infrastructure generated calls such as fire house, rail infrastructure, roadwork site, etc.
* - 12 - `police`          - Police vehicle
* - 13 - `fire`            - Firebrigade
* - 14 - `ambulance`       - (does not include private para-transit etc.)
* - 15 - `dot`             - all roadwork vehicles
* - 16 - `transit`         - all transit vehicles
* - 17 - `slowMoving`      - to also include oversize etc.
* - 18 - `stopNgo`         - to include trash trucks, school buses and others
* - 19 - `cyclist`         - bicycles
* - 20 - `pedestrian`      - also includes those with mobility limitations
* - 21 - `nonMotorized`    - other, horse drawn, etc.
* - 22 - `military`        - military vehicles
*
* @note: It should be observed that devices can at times change their roles (i.e. a fire operated by a volunteer
*    fireman can assume a fire role for a period of time when in service, or a pedestrian may assume a cyclist role when using
*    a bicycle). It should be observed that not all devices (or vehicles) can assume all roles, nor that a given
*    device in a given role will be provided with a security certificate (CERT) that has suitable SSP credentials to provide the
*    ability to send a particular message or message content. The ultimate responsibility to determine what role is to be used,
*    and what CERTs would be provided for that role (which in turn controls the messages and message content that can be
*    sent within SAE-defined PSIDs) rests with the regional deployment.
* @category: Infrastructure information
* @revision: V1.3.1
*/
BasicVehicleRole ::= ENUMERATED {
  basicVehicle     (0),
  publicTransport  (1),
  specialTransport (2),
  dangerousGoods   (3),
  roadWork         (4),
  roadRescue       (5),
  emergency        (6),
  safetyCar        (7),
  none-unknown     (8),
  truck            (9),
  motorcycle      (10),
  roadSideSource  (11),
  police          (12),
  fire            (13),
  ambulance       (14),
  dot             (15),
  transit         (16),
  slowMoving      (17),
  stopNgo         (18),
  cyclist         (19),
  pedestrian      (20),
  nonMotorized    (21),
  military        (22),
  ...,
  tram            (23)   -- Extension in V2.2.1
}

/**
* The DSRC style day is a simple value consisting of integer values from zero to 31. The value of zero shall represent an unknown value.
*
* @unit: days
* @category: Infrastructure information
* @revision: V1.3.1
*/
DDay ::= INTEGER (0..31)

/**
* This DE provides the final angle used in the last point of the lane path. Used to "cant" the stop line of the lane.
*
* With an angle range from negative 150 to positive 150 in one degree steps where zero is directly
* along the axis or the lane center line as defined by the two closest points.
*
* @unit: degree
* @category: Infrastructure information
* @revision: V1.3.1
*/
DeltaAngle ::= INTEGER (-150..150)

/**
* This DE provides a time definition for an object's schedule adherence (typically a transit
* vehicle) within a limited range of time. When the reporting object is ahead of schedule, a positive value is used; when
* behind, a negative value is used. A value of zero indicates schedule adherence. This value is typically sent from a vehicle
* to the traffic signal controller's RSU to indicate the urgency of a signal request in the context of being within schedule or
* not. In another use case, the traffic signal controller may advise the transit vehicle to speed up (DeltaTime > 0) or to slow
* down (DeltaTime < 0) to optimize the transit vehicle distribution driving along a specific route (e.g. a Bus route).
*
* Supporting a range of +/- 20 minute in steps of 10 seconds:
* - the value of `-121` shall be used when more than -20 minutes
* - the value of `+120` shall be used when more than +20 minutes
* - the value `-122` shall be used when the value is unavailable
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
DeltaTime ::= INTEGER (-122 .. 121)

/**
* This DE is used in maps and intersections to provide a human readable and
* recognizable name for the feature that follows. It is typically used when debugging a data flow and not in production use.
* One key exception to this general rule is to provide a human-readable string for disabled travelers in the case of
* crosswalks and sidewalk lane objects.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
DescriptiveName ::= IA5String (SIZE(1..63))

/**
* The DSRC hour consists of integer values from zero to 23 representing the hours within a day. The value of 31 shall
* represent an unknown value. The range 24 to 30 is used in some transit applications to represent schedule adherence.
*
* @unit: hours
* @category: Infrastructure information
* @revision: V1.3.1
*/
DHour ::= INTEGER (0..31)

/**
* The DSRC style minute is a simple value consisting of integer values from zero to 59 representing the minutes
* within an hour. The value of 60 shall represent an unknown value.
*
* @unit: minutes
* @category: Infrastructure information
* @revision: V1.3.1
*/
DMinute ::= INTEGER (0..60)

/**
* The DSRC month consists of integer values from one to 12, representing the month within a year. The value of 0
* shall represent an unknown value.
*
* @unit: months
* @category: Infrastructure information
* @revision: V1.3.1
*/
DMonth ::= INTEGER (0..12)

/**
* The DSRC (time zone) offset consists of a signed integer representing an hour and minute value set from -14:00 to
* +14:00, representing all the world’s local time zones in units of minutes. The value of zero (00:00) may also represent an
* unknown value. Note some time zones are do not align to hourly boundaries.
*
* @unit: minutes from UTC time
* @category: Infrastructure information
* @revision: V1.3.1
*/
DOffset ::= INTEGER (-840..840)

/**
* This DE is an integer value expressing the offset in a defined axis from a
* reference lane number from which a computed lane is offset. The measurement is taken from the reference lane center
* line to the new center line, independent of any width values. The units are a signed value with an LSB of 1 cm.
*
* @unit: cm
* @category: Infrastructure information
* @revision: V1.3.1
*/
DrivenLineOffsetLg ::= INTEGER (-32767..32767)

/**
* The DrivenLineOffsetSmall data element is an integer value expressing the offset in a defined axis from a reference
* lane number from which a computed lane is offset. The measurement is taken from the reference lane center line to the
* new center line, independent of any width values. The units are a signed value with an LSB of 1 cm.
*
* @unit: cm
* @category: Infrastructure information
* @revision: V1.3.1
*/
DrivenLineOffsetSm ::= INTEGER (-2047..2047)

/**
* The DSRC second expressed in this DE consists of integer values from zero to 60999, representing the
* milliseconds within a minute. A leap second is represented by the value range 60000 to 60999. The value of 65535 shall
* represent an unavailable value in the range of the minute. The values from 61000 to 65534 are reserved.
*
* @unit: milliseconds
* @category: Infrastructure information
* @revision: V1.3.1
*/
DSecond ::= INTEGER (0..65535)

/**
* The DSRC year consists of integer values from zero to 4095 representing the year according to the Gregorian
* calendar date system. The value of zero shall represent an unknown value.
*
* @unit: years
* @category: Infrastructure information
* @revision: V1.3.1
*/
DYear ::= INTEGER (0..4095)

/**
* This DE represents the geographic position above or below the reference ellipsoid (typically WGS-84).
* The number has a resolution of 1 decimeter and represents an asymmetric range of positive and negative
* values. Any elevation higher than +6143.9 meters is represented as +61439.
*
* Any elevation lower than -409.5 meters is represented as -4095.
*
* If the sending device does not know its elevation, it shall encode the Elevation data element with -4096.
*
* @note: When a vehicle is being measured, the elevation is taken from the horizontal spatial center of the vehicle
*        projected downward, regardless of vehicle tilt, to the point where the vehicle meets the road surface.
* @category: Infrastructure information
* @revision: V1.3.1
*/
Elevation ::= INTEGER (-4096..61439)

/**
* This DE is used to provide the 95% confidence level for the currently reported value of @ref Elevation,
* taking into account the current calibration and precision of the sensor(s) used to measure and/or
* calculate the value. This data element is only to provide the listener with information on the limitations of the sensing
* system, not to support any type of automatic error correction or to imply a guaranteed maximum error. This data element
* should not be used for fault detection or diagnosis, but if a vehicle is able to detect a fault, the confidence interval should
* be increased accordingly. The frame of reference and axis of rotation used shall be in accordance with that defined in Section 11.
*
* - `unavailable` - 0:   B'0000 Not Equipped or unavailable
* - `elev-500-00` - 1:   B'0001 (500 m)
* - `elev-200-00` - 2:   B'0010 (200 m)
* - `elev-100-00` - 3:   B'0011 (100 m)
* - `elev-050-00` - 4:   B'0100 (50 m)
* - `elev-020-00` - 5:   B'0101 (20 m)
* - `elev-010-00` - 6:   B'0110 (10 m)
* - `elev-005-00` - 7:   B'0111 (5 m)
* - `elev-002-00` - 8:   B'1000 (2 m)
* - `elev-001-00` - 9:   B'1001 (1 m)
* - `elev-000-50` - 10:  B'1010 (50 cm)
* - `elev-000-20` - 11:  B'1011 (20 cm)
* - `elev-000-10` - 12:  B'1100 (10 cm)
* - `elev-000-05` - 13:  B'1101 (5 cm)
* - `elev-000-02` - 14:  B'1110 (2 cm)
* - `elev-000-01` - 15:  B'1111 (1 cm)
*
* @note: Encoded as a 4 bit value
* @category: Infrastructure information
* @revision: V1.3.1
*/
ElevationConfidence ::= ENUMERATED {
   unavailable (0),
   elev-500-00 (1),
   elev-200-00 (2),
   elev-100-00 (3),
   elev-050-00 (4),
   elev-020-00 (5),
   elev-010-00 (6),
   elev-005-00 (7),
   elev-002-00 (8),
   elev-001-00 (9),
   elev-000-50 (10),
   elev-000-20 (11),
   elev-000-10 (12),
   elev-000-05 (13),
   elev-000-02 (14),
   elev-000-01 (15)
}

/**
* This DE provides the type of fuel used by a vehicle.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
FuelType ::= INTEGER (0..15)
   unknownFuel FuelType  ::= 0
   gasoline FuelType     ::= 1
   ethanol FuelType      ::= 2
   diesel FuelType       ::= 3
   electric FuelType     ::= 4
   hybrid FuelType       ::= 5
   hydrogen FuelType     ::= 6
   natGasLiquid FuelType ::= 7
   natGasComp FuelType   ::= 8
   propane FuelType      ::= 9

/**
* This DE is used to relate the current state of a GPS/GNSS rover or base system in terms
* of its general health, lock on satellites in view, and use of any correction information. Various bits can be asserted (made
* to a value of one) to reflect these values. A GNSS set with unknown health and no tracking or corrections would be
* represented by setting the unavailable bit to one. A value of zero shall be used when a defined data element is
* unavailable. The term "GPS" in any data element name in this standard does not imply that it is only to be used for GPS-
* type GNSS systems.
*
* - `unavailable`              - 0: Not Equipped or unavailable
* - `isHealthy`                - 1:
* - `isMonitored`              - 2:
* - `baseStationType`          - 3: Set to zero if a moving base station, or if a rover device (an OBU), Set to one if it is a fixed base station
* - `aPDOPofUnder5`            - 4: A dilution of precision greater than 5
* - `inViewOfUnder5`           - 5: Less than 5 satellites in view
* - `localCorrectionsPresent`  - 6: DGPS type corrections used
* - `networkCorrectionsPresen` - 7: RTK type corrections used
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
GNSSstatus ::= BIT STRING {
   unavailable               (0),
   isHealthy                 (1),
   isMonitored               (2),
   baseStationType           (3),
   aPDOPofUnder5             (4),
   inViewOfUnder5            (5),
   localCorrectionsPresent   (6),
   networkCorrectionsPresent (7)
 } (SIZE(8))

/**
* The DE_HeadingConfidence data element is used to provide the 95% confidence level for the currently reported
* calculate the value. This data element is only to provide the listener with information on the limitations of the sensing
* value of DE_Heading, taking into account the current calibration and precision of the sensor(s) used to measure and/or
* system, not to support any type of automatic error correction or to imply a guaranteed maximum error. This data element
* should not be used for fault detection or diagnosis, but if a vehicle is able to detect a fault, the confidence interval should
* be increased accordingly. The frame of reference and axis of rotation used shall be in accordance with that defined Section 11.
*
* - `unavailable`   - 0: B'000 Not Equipped or unavailable
* - `prec10deg`     - 1: B'010 10 degrees
* - `prec05deg`     - 2: B'011 5 degrees
* - `prec01deg`     - 3: B'100 1 degrees
* - `prec0-1deg`    - 4: B'101 0.1 degrees
* - `prec0-05deg`   - 5: B'110 0.05 degrees
* - `prec0-01deg`   - 6: B'110 0.01 degrees
* - `prec0-0125deg` - 7: B'111 0.0125 degrees, aligned with heading LSB
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
HeadingConfidenceDSRC ::= ENUMERATED {
   unavailable   (0),
   prec10deg     (1),
   prec05deg     (2),
   prec01deg     (3),
   prec0-1deg    (4),
   prec0-05deg   (5),
   prec0-01deg   (6),
   prec0-0125deg (7)
}

/**
* This DE provides the current heading of the sending device, expressed in unsigned units of
* 0.0125 degrees from North such that 28799 such degrees represent 359.9875 degrees. North shall be defined as the axis
* prescribed by the WGS-84 coordinate system and its reference ellipsoid. Headings "to the east" are defined as the
* positive direction. A value of 28800 shall be used when unavailable. This element indicates the direction of motion of the
* device. When the sending device is stopped and the trajectory (path) over which it traveled to reach that location is well
* known, the past heading may be used.
*
* Value provides a range of 0 to 359.9875 degrees
*
* @unit: Note that other heading data elements of various sizes and precisions are found in other parts of this standard
*        and in ITS. This element should no longer be used for new work: the @ref Angle entry is preferred.
*
* @unit: 0.0125 degrees
* @category: Infrastructure information
* @revision: V1.3.1
*/
HeadingDSRC ::= INTEGER (0..28800)

/**
* This DE is used within a region to uniquely define an intersection within that country or region in a 16-bit
* field. Assignment rules are established by the regional authority associated with the RoadRegulatorID under which this
* IntersectionID is assigned. Within the region the policies used to ensure an assigned value’s uniqueness before that value
* is reused (if ever) is the responsibility of that region. Any such reuse would be expected to occur over a long epoch (many years).
* The values zero through 255 are allocated for testing purposes
*
* @note:  Note that the value assigned to an intersection will be unique within a given regional ID only
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionID ::= INTEGER (0..65535)

/**
* The Intersection Status Object contains Advanced Traffic Controller (ATC) status information that may be sent to
* local OBUs as part of the SPAT process.
*
* With bits as defined:
* - `manualControlIsEnabled`                - 0: Timing reported is per programmed values, etc. but person at cabinet can manually request that certain intervals are terminated early (e.g. green).
* - `stopTimeIsActivated`                   - 1: And all counting/timing has stopped.
* - `failureFlash`                          - 2: Above to be used for any detected hardware failures, e.g. conflict monitor as well as for police flash
* - `fixedTimeOperation`                    - 5: Schedule of signals is based on time only (i.e. the state can be calculated)
* - `trafficDependentOperation`             - 6: Operation is based on different levels of traffic parameters (requests, duration of gaps or more complex parameters)
* - `standbyOperation`                      - 7: Controller: partially switched off or partially amber flashing
* - `failureMode`                           - 8: Controller has a problem or failure in operation
* - `off`                                   - 9: Controller is switched off
* - `recentMAPmessageUpdate`                - 10: Map revision with content changes
* - `recentChangeInMAPassignedLanesIDsUsed` - 11: Change in MAP's assigned lanes used (lane changes) Changes in the active lane list description
* - `noValidMAPisAvailableAtThisTime`       - 12: MAP (and various lanes indexes) not available
* - `noValidSPATisAvailableAtThisTime`      - 13: SPAT system is not working at this time
* - Bits 14,15 reserved at this time and shall be zero
*
* @note: All zeros indicate normal operating mode with no recent changes. The duration of the term **recent** is defined by the system performance requirement in use.
* @category: Infrastructure information
* @revision: V1.3.1
*/
IntersectionStatusObject ::= BIT STRING {
  manualControlIsEnabled                (0),
  stopTimeIsActivated                   (1),
  failureFlash                          (2),
  preemptIsActive                       (3),
  signalPriorityIsActive                (4),
  fixedTimeOperation                    (5),
  trafficDependentOperation             (6),
  standbyOperation                      (7),
  failureMode                           (8),
  off                                   (9),
  recentMAPmessageUpdate                (10),
  recentChangeInMAPassignedLanesIDsUsed (11),
  noValidMAPisAvailableAtThisTime       (12),
  noValidSPATisAvailableAtThisTime      (13)
} (SIZE(16))

/**
* This DE relates specific properties found in a Barrier or Median lane type (a type of lane object used to separate traffic lanes).
* It should be noted that various common lane attribute properties (such as travel directions and allowed movements or maneuvers) can be found in other entries.
*
* With bits as defined:
* - `median-RevocableLane` - 0: this lane may be activated or not based on the current SPAT message contents if not asserted, the lane is ALWAYS present
* - Bits 10-15 reserved and set to zero
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-Barrier ::= BIT STRING {
  median-RevocableLane     (0),
  median                   (1),
  whiteLineHashing         (2),
  stripedLines             (3),
  doubleStripedLines       (4),
  trafficCones             (5),
  constructionBarrier      (6),
  trafficChannels          (7),
  lowCurbs                 (8),
  highCurbs                (9)
} (SIZE (16))

/**
* This DE relates specific properties found in a bicycle lane type. It should be noted that various common lane attribute properties
* (such as travel directions and allowed movements or maneuvers) can be found in other entries.
*
* With bits as defined:
* - `bikeRevocableLane`       - 0: this lane may be activated or not based on the current SPAT message contents if not asserted, the lane is ALWAYS present
* - `pedestrianUseAllowed`    - 1: The path allows pedestrian traffic, if not set, this mode is prohibited
* - `isBikeFlyOverLane`       - 2: path of lane is not at grade
* - `fixedCycleTime`          - 3: the phases use preset times, i.e. there is not a **push to cross** button
* - `biDirectionalCycleTimes` - 4: ped walk phases use different SignalGroupID for each direction. The first SignalGroupID in the first Connection
*                                  represents **inbound** flow (the direction of travel towards the first node point) while second SignalGroupID in the
*                                  next Connection entry represents the `outbound` flow. And use of RestrictionClassID entries in the Connect follow this same pattern in pairs.
* - `isolatedByBarrier`           - 5: The lane path is isolated by a fixed barrier
* - `unsignalizedSegmentsPresent` - 6: The lane path consists of one of more segments which are not part of a signal group ID
* - Bits 7-15 reserved and set to zero
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-Bike ::= BIT STRING {
  bikeRevocableLane       (0),
  pedestrianUseAllowed    (1),
  isBikeFlyOverLane       (2),
  fixedCycleTime          (3),
  biDirectionalCycleTimes (4),
  isolatedByBarrier       (5),
  unsignalizedSegmentsPresent  (6)
} (SIZE (16))

/**
* This DE relates specific properties found in a crosswalk lane type. It should be noted that various common lane attribute properties
* (such as travel directions and allowed movements or maneuvers) can be found in other entries.
*
* With bits as defined:
* - `crosswalkRevocableLane`  - 0:  this lane may be activated or not based on the current SPAT message contents if not asserted, the lane is ALWAYS present
* - `bicyleUseAllowed`        - 1: The path allows bicycle traffic, if not set, this mode is prohibited
* - `isXwalkFlyOverLane`      - 2: path of lane is not at grade
* - `fixedCycleTime`          - 3: ped walk phases use preset times. i.e. there is not a **push to cross** button
* - `biDirectionalCycleTimes` - 4:  ped walk phases use different SignalGroupID for each direction. The first SignalGroupID
*                                   in the first Connection represents **inbound** flow (the direction of travel towards the first
*                                   node point) while second SignalGroupID in the next Connection entry represents the **outbound**
*                                   flow. And use of RestrictionClassID entries in the Connect follow this same pattern in pairs.
* - `hasPushToWalkButton`     - 5: Has a demand input
* - `audioSupport`            - 6:  audio crossing cues present
* - `rfSignalRequestPresent`  - 7: Supports RF push to walk technologies
* - `unsignalizedSegmentsPresent` - 8: The lane path consists of one of more segments which are not part of a signal group ID
* - Bits 9-15 reserved and set to zero
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-Crosswalk ::= BIT STRING {
  crosswalkRevocableLane  (0),
  bicyleUseAllowed        (1),
  isXwalkFlyOverLane      (2),
  fixedCycleTime          (3),
  biDirectionalCycleTimes (4),
  hasPushToWalkButton     (5),
  audioSupport            (6),
  rfSignalRequestPresent  (7),
  unsignalizedSegmentsPresent  (8)
} (SIZE (16))

/**
* This DE relates specific properties found in a vehicle parking lane type. It should be noted that various common lane attribute
* properties can be found in other entries.
*
* With bits as defined:
* - `parkingRevocableLane` - 0: this lane may be activated or not based on the current SPAT message contents if not asserted, the lane is ALWAYS present
* - `doNotParkZone`        - 3: used to denote fire hydrants as well as short disruptions in a parking zone
* - `noPublicParkingUse`   - 6: private parking, as in front of private property
* - Bits 7-15 reserved and set to zero*
*
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-Parking ::= BIT STRING {
  parkingRevocableLane         (0),
  parallelParkingInUse         (1),
  headInParkingInUse           (2),
  doNotParkZone                (3),
  parkingForBusUse             (4),
  parkingForTaxiUse            (5),
  noPublicParkingUse           (6)
} (SIZE (16))

/**
* This DE relates specific properties found in a sidewalk lane type. It should be noted that various common lane attribute properties
* (such as travel directions and allowed movements or maneuvers) can be found in other entries.
*
* With bits as defined:
* - `sidewalk-RevocableLane`- 0: this lane may be activated or not based on the current SPAT message contents if not asserted, the lane is ALWAYS present.
* - `bicyleUseAllowed`      - 1: The path allows bicycle traffic, if not set, this mode is prohibited
* - `isSidewalkFlyOverLane` - 2: path of lane is not at grade
* - `walkBikes`             - 3: bike traffic must dismount and walk
* - Bits 4-15 reserved and set to zero
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-Sidewalk ::= BIT STRING {
  sidewalk-RevocableLane  (0),
  bicyleUseAllowed        (1),
  isSidewalkFlyOverLane   (2),
  walkBikes               (3)
} (SIZE (16))

/**
* This DE relates specific properties found in various types of ground striping lane
* types. This includes various types of painted lane ground striping and iconic information needs to convey information in a
* complex intersection. Typically, this consists of visual guidance for drivers to assist them to connect across the
* intersection to the correct lane. Such markings are typically used with restraint and only under conditions when the
* geometry of the intersection makes them more beneficial than distracting. It should be noted that various common lane
* attribute properties (such as travel directions and allowed movements or maneuvers) can be found in other entries.
*
* With bits as defined:
* - `stripeToConnectingLanesRevocableLane` - 0: this lane may be activated or not activated based on the current SPAT message contents if not asserted, the lane is ALWAYS present
* - `stripeToConnectingLanesAhead` - 5: the stripe type should be presented to the user visually to reflect stripes in the intersection for the type of movement indicated.
* - Bits 6-15 reserved and set to zero
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-Striping ::= BIT STRING {
  stripeToConnectingLanesRevocableLane      (0),
  stripeDrawOnLeft                          (1),
  stripeDrawOnRight                         (2),
  stripeToConnectingLanesLeft               (3),
  stripeToConnectingLanesRight              (4),
  stripeToConnectingLanesAhead              (5)
} (SIZE (16))

/**
* This DE relates specific properties found in a tracked vehicle lane types (trolley
* and train lanes). The term “rail vehicle” can be considered synonymous. In this case, the term does not relate to vehicle
* types with tracks or treads. It should be noted that various common lane attribute properties (such as travel directions and
* allowed movements or maneuvers) can be found in other entries. It should also be noted that often this type of lane object
* does not clearly relate to an approach in the traditional traffic engineering sense, although the message set allows
* assigning a value when desired.
*
* With bits as defined:
* - `spec-RevocableLane` - 0: this lane may be activated or not based on the current SPAT message contents if not asserted, the lane is ALWAYS present.
* - Bits 5-15 reserved and set to zero
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-TrackedVehicle ::= BIT STRING {
  spec-RevocableLane         (0),
  spec-commuterRailRoadTrack (1),
  spec-lightRailRoadTrack    (2),
  spec-heavyRailRoadTrack    (3),
  spec-otherRailType         (4)
} (SIZE (16))


/**
* This DE relates specific properties found in a vehicle lane type. This data element provides a means to denote that the use of a lane
* is restricted to certain vehicle types. Various common lane attribute properties (such as travel directions and allowed movements or maneuvers)
* can be found in other entries.
*
* With bits as defined:
* - `isVehicleRevocableLane` - 0: this lane may be activated or not based on the current SPAT message contents if not asserted, the lane is ALWAYS present
* - `isVehicleFlyOverLane`   - 1: path of lane is not at grade
* - `permissionOnRequest`    - 7: e.g. to inform about a lane for e-cars
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneAttributes-Vehicle ::= BIT STRING {
  isVehicleRevocableLane       (0),
  isVehicleFlyOverLane         (1),
  hovLaneUseOnly               (2),
  restrictedToBusUse           (3),
  restrictedToTaxiUse          (4),
  restrictedFromPublicUse      (5),
  hasIRbeaconCoverage          (6),
  permissionOnRequest          (7)
} (SIZE (8,...))

/**
* This DE is used to state a connection index for a lane to lane connection. It is used to
* relate this connection between the lane (defined in the MAP) and any dynamic clearance data sent in the SPAT. It should
* be noted that the index may be shared with other lanes (for example, two left turn lanes may share the same dynamic
* clearance data). It should also be noted that a given lane to lane connection may be part of more than one GroupID due
* to signal phase considerations, but will only have one ConnectionID. The ConnectionID concept is not used (is not
* present) when dynamic clearance data is not provided in the SPAT.
*
* @note: It should be noted that the LaneConnectionID is used as a means to index to a connection description
*        between two lanes. It is not the same as the laneID, which is the unique index to each lane itself.
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneConnectionID ::= INTEGER (0..255)

/**
* This DE is used to denote the allowed direction of travel over a lane object. By convention, the lane object is always described
* from the stop line outwards away from the intersection. Therefore, the ingress direction is from the end of the path to the stop
* line and the egress direction is from the stop line outwards.
*
* It should be noted that some lane objects are not used for travel and that some lane objects allow bi-directional travel.
*
* With bits as defined:
* - Allowed directions of travel in the lane object
* - All lanes are described from the stop line outwards
*
* @field ingressPath: travel from rear of path to front is allowed
*
* @field egressPath: travel from front of path to rear is allowed
*
* @note: No Travel, i.e. the lane object type does not support travel (medians, curbs, etc.) is indicated by not
*        asserting any bit value Bi-Directional Travel (such as a ped crosswalk) is indicated by asserting both of the bits.
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneDirection ::= BIT STRING {
  ingressPath     (0),
  egressPath      (1)
} (SIZE (2))

/**
* This DE conveys an assigned index that is unique within an intersection. It is used to refer to
* that lane by other objects in the intersection map data structure. Lanes may be ingress (inbound traffic) or egress
* (outbound traffic) in nature, as well as barriers and other types of specialty lanes. Each lane (each lane object) is
* assigned a unique ID. The Lane ID, in conjunction with the intersection ID, forms a regionally unique way to address a
* specific lane in that region.
*
* - the value 0 shall be used when the lane ID is not available or not known
* - the value 255 is reserved for future use
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneID ::= INTEGER (0..255)

/**
* Large @ref MapData descriptions are not possible to be broadcast with a single message and have to be
* fragmented using two or more messages over the air. Therefore, the LayerID allows defining an
* index for fragmentation of large @ref MapData descriptions. The fragmentation of the messages shall be
* executed on application layer. The fragmentation occurs on an approach base. This means that almost a
* complete approach (e.g. lanes, connectsTo, etc.) has to be included within a fragment.
* The decimal value of the **layerID** is used to define the amount of maximum @ref MapData fragments. The
* lower value defines the actual fragment.
*
* Example:
* If a MapData consists of three fragments (e.g. three approaches), the fragments are identified as follows:
* - `31` - first fragment of three (e.g. approach south);
* - `33` - third fragment of three (e.g. approach north).
* - `32` - second fragment of three (e.g. approach west);
*
* If there are only two fragments, the fragment identification will be 21, 22.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LayerID ::= INTEGER (0..100)

/**
* This DE is used to uniquely identify the type of information to be found in a layer of a geographic map fragment such as an intersection.
*
* @field `mixedContent`: two or more of the below types
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
LayerType ::= ENUMERATED {
  none,
  mixedContent,
  generalMapData,
  intersectionData,
  curveData,
  roadwaySectionData,
  parkingAreaData,
  sharedLaneData,
  ...
}

/**
* This DE conveys the width of a lane in LSB units of 1 cm. Maximum value for a lane is 327.67 meters in width
*
* @units: cm
* @category: Infrastructure information
* @revision: V1.3.1
*/
LaneWidth ::= INTEGER (0..32767)

/**
* This DE is used to provide the R09 line information.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
LineNumber ::= INTEGER (0..4294967295)

/**
* The angle at which another lane path meets the current lanes at the node point. Typically found in the node
* attributes and used to describe the angle of the departing or merging lane. Note that oblique and obtuse angles are allowed.
*
* The value `-180` shall be used to represent data is not available or unknown
*
* @unit: 1.5 degrees from north
* @category: Infrastructure information
* @revision: V1.3.1
*/
MergeDivergeNodeAngle ::= INTEGER (-180..180)

/**
* This DE expresses the number of elapsed minutes of the current year in the time system being used (typically UTC time).
*
* It is typically used to provide a longer range time stamp indicating when a message was created.
* Taken together with the DSecond data element, it provides a range of one full year with a resolution of 1 millisecond.
*
* The value 527040 shall be used for invalid.
*
* @note: It should be noted that at the yearly roll-over point there is no "zero" minute, in the same way that there was
*        never a "year zero" at the very start of the common era (BC -> AD). By using the number of elapsed whole minutes here
*        this issue is avoided and the first valid value of every new year is zero, followed by one, etc. Leap years are
*        accommodated, as are leap seconds in the DSecond data concept.
* @category: Infrastructure information
* @revision: V1.3.1
*/
MinuteOfTheYear ::= INTEGER (0..527040)

/**
* This DE provides the overall current state of the movement (in many cases a signal state), including its core phase state
*  and an indication of whether this state is permissive or protected.
*
* It is expected that the allowed transitions from one state to another will be defined by regional deployments. Not all
* regions will use all states; however, no new states are to be defined. In most regions a regulatory body provides precise
* legal definitions of these state changes. For example, in the US the MUTCD is used, as is indicated in the US regional
* variant of the above image. In various regions and modes of transportation, the visual expression of these states varies
* (the precise meaning of various color combinations, shapes, and/or flashing etc.). The below definition is designed to to
* be independent of these regional conventions.
*
* Values:
* - `unavailable` - 0:         This state is used for unknown or error
* - `dark` - 1:                The signal head is dark (unlit)
* - `stop-Then-Proceed` - 2:   Often called **flashing red**
*                              Driver Action:
*                              - Stop vehicle at stop line.
*                              - Do not proceed unless it is safe.
*                              Note that the right to proceed either right or left when it is safe may be contained in the lane description to
*                              handle what is called a **right on red**
* - `stop-And-Remain` - 3:     e.g. called **red light**
*                              Driver Action:
*                              - Stop vehicle at stop line.
*                              - Do not proceed.
*                              Note that the right to proceed either right or left when it is safe may be contained in the lane description to
*                              handle what is called a **right on red**
* - `pre-Movement` - 4:        Not used in the US, red+yellow partly in EU
*                              Driver Action:
*                              - Stop vehicle.
*                              - Prepare to proceed (pending green)
*                              - (Prepare for transition to green/go)
* - `permissive-Movement-Allowed` - 5: Often called **permissive green**
*                              Driver Action:
*                              - Proceed with caution,
*                              - must yield to all conflicting traffic
*                              Conflicting traffic may be present in the intersection conflict area
* - `protected-Movement-Allowed` - 6: Often called **protected green**
*                              Driver Action:
*                              - Proceed, tossing caution to the wind, in indicated (allowed) direction.
* - `permissive-clearance` - 7: Often called **permissive yellow**.
*                              The vehicle is not allowed to cross the stop bar if it is possible
*                              to stop without danger.
*                              Driver Action:
*                              - Prepare to stop.
*                              - Proceed if unable to stop,
*                              - Clear Intersection.
*                              Conflicting traffic may be present in the intersection conflict area
* - `protected-clearance` - 8:  Often called **protected yellow**
*                              Driver Action:
*                              - Prepare to stop.
*                              - Proceed if unable to stop, in indicated direction (to connected lane)
*                              - Clear Intersection.
* - `caution-Conflicting-Traffic` - 9: Often called **flashing yellow**
*                              Often used for extended periods of time
*                              Driver Action:
*                              - Proceed with caution,
*                              Conflicting traffic may be present in the intersection conflict area
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
MovementPhaseState ::= ENUMERATED {
  unavailable (0),
  dark (1),
  stop-Then-Proceed (2),
  stop-And-Remain (3),
  pre-Movement (4),
  permissive-Movement-Allowed (5),
  protected-Movement-Allowed (6),
  permissive-clearance (7),
  protected-clearance (8),
  caution-Conflicting-Traffic (9)
}

/**
* This DE is used to provide a sequence number within a stream of messages with the same DSRCmsgID and from the same sender.
* A sender may initialize this element to any value in the range 0-127 when sending the first message with a given DSRCmsgID,
* or if the sender has changed identity (e.g. by changing its TemporaryID) since sending the most recent message with that DSRCmsgID.
*
* Depending on the application the sequence number may change with every message or may remain fixed during a stream of messages when the content within each
* message has not changed from the prior message sent. For this element, the value after 127 is zero.
*
* The receipt of a non-sequential MsgCount value (from the same sending device and message type) implies that one or
* more messages from that sending device may have been lost, unless MsgCount has been re-initialized due to an identity
* change.
*
* @note: In the absence of additional requirements defined in a standard using this data element, the follow guidelines shall be used.
*
* In usage, some devices change their Temporary ID frequently, to prevent identity tracking, while others do not. A change
* in Temporary ID data element value (which also changes the message contents in which it appears) implies that the
* MsgCount may also change value.
*
* If a sender is composing a message with new content with a given DSRCmsgID, and the TemporaryID has not changed
* since it sent the previous message, the sender shall increment the previous value.
* If a sender is composing a message with new content with a given DSRCmsgID, and the TemporaryID has changed since
* it sent the previous message, the sender may set the MsgCount element to any valid value in the range (including
* incrementing the previous value).
*
* If a sender is composing a message with the same content as the most recent message with the same DSRCmsgID, and
* less than 10 seconds have elapsed since it sent the previous message with that DSRCmsgID, the sender will use the
* same MsgCount as sent in the previous message.
*
* If a sender is composing a message with the same content as the most recent message with the same DSRCmsgID, and
* at least 10 seconds have elapsed since it sent the previous message with that DSRCmsgID, the sender may set the
* MsgCount element to any valid value in the range; this includes the re-use of the previous value.
*
* If a sending device sends more than one stream of messages from message types that utilize the MsgCount element, it
* shall maintain a separate MsgCount state for each message type so that the MsgCount value in a given message
* identifies its place in the stream of that message type. The MsgCount element is a function only of the message type in a
* given sending device, not of the one or more applications in that device which may be sending the same type of message.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
MsgCount ::= INTEGER (0..127)

/**
* A 9-bit delta offset in X, Y or Z direction from some known point. For non-vehicle centric coordinate frames of
* reference, offset is positive to the East (X) and to the North (Y) directions. The most negative value shall be used to
* indicate an unknown value.
* a range of +- 2.55 meters
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Offset-B09 ::= INTEGER (-256..255)

/**
* A 10-bit delta offset in X, Y or Z direction from some known point. For non-vehicle centric coordinate frames of
* reference, offset is positive to the East (X) and to the North (Y) directions. The most negative value shall be used to
* indicate an unknown value.
* a range of +- 5.11 meters
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Offset-B10 ::= INTEGER (-512..511)

/**
* An 11-bit delta offset in X or Y direction from some known point. For non-vehicle centric coordinate frames of
* reference, offset is positive to the East (X) and to the North (Y) directions. The most negative value shall be used to
* indicate an unknown value.
* a range of +- 10.23 meters
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Offset-B11 ::= INTEGER (-1024..1023)

/**
* A 12-bit delta offset in X, Y or Z direction from some known point. For non-vehicle centric coordinate frames of
* reference, non-vehicle centric coordinate frames of reference, offset is positive to the East (X) and to the North (Y)
* directions. The most negative value shall be used to indicate an unknown value.
* a range of +- 20.47 meters
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Offset-B12 ::= INTEGER (-2048..2047)

/**
* A 13-bit delta offset in X or Y direction from some known point. For non-vehicle centric coordinate frames of
* reference, offset is positive to the East (X) and to the North (Y) directions. The most negative value shall be used to
* indicate an unknown value.
* a range of +- 40.95 meters
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Offset-B13 ::= INTEGER (-4096..4095)

/**
* A 14-bit delta offset in X or Y direction from some known point. For non-vehicle centric coordinate frames of
* reference, offset is positive to the East (X) and to the North (Y) directions.
* a range of +- 81.91 meters
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Offset-B14 ::= INTEGER (-8192..8191)

/**
* A 16-bit delta offset in X, Y or Z direction from some known point. For non-vehicle centric coordinate frames of
* reference, offset is positive to the East (X) and to the North (Y) directions. The most negative value shall be used to
* indicate an unknown value.
* a range of +- 327.68 meters
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
Offset-B16 ::= INTEGER (-32768..32767)

/**
* This DE is used to provide an indication of whether Pedestrians and/or Bicyclists have been detected in the crossing lane.
* true if ANY Pedestrians or Bicyclists are detected crossing the target lane or lanes
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
PedestrianBicycleDetect ::= BOOLEAN

/**
* This DE entry is used to provide the 95% confidence level for the currently reported value of
* entries such as the DE_Position entries, taking into account the current calibration and precision of the sensor(s) used to
* measure and/or calculate the value. It is used in the horizontal plane. This data element is only to provide the listener with
* information on the limitations of the sensing system; not to support any type of automatic error correction or to imply a
* guaranteed maximum error. This data element should not be used for fault detection or diagnosis, but if a vehicle is able
* to detect a fault, the confidence interval should be increased accordingly. The frame of reference and axis of rotation used
* shall be accordance with that defined in Section 11 of this standard.
*
* - `unavailable` - 0: B'0000 Not Equipped or unavailable
* - `a500m`       - 1: B'0001 500m or about 5 * 10 ^ -3 decimal degrees
* - `a200m`       - 2: B'0010 200m or about 2 * 10 ^ -3 decimal degrees
* - `a100m`       - 3: B'0011 100m or about 1 * 10 ^ -3 decimal degrees
* - `a50m`        - 4: B'0100 50m or about 5 * 10 ^ -4 decimal degrees
* - `a20m`        - 5: B'0101 20m or about 2 * 10 ^ -4 decimal degrees
* - `a10m`        - 6: B'0110 10m or about 1 * 10 ^ -4 decimal degrees
* - `a5m`         - 7: B'0111 5m or about 5 * 10 ^ -5 decimal degrees
* - `a2m`         - 8: B'1000 2m or about 2 * 10 ^ -5 decimal degrees
* - `a1m`         - 9: B'1001 1m or about 1 * 10 ^ -5 decimal degrees
* - `a50cm`       - 10: B'1010 0.50m or about 5 * 10 ^ -6 decimal degrees
* - `a20cm`       - 11: B'1011 0.20m or about 2 * 10 ^ -6 decimal degrees
* - `a10cm`       - 12: B'1100 0.10m or about 1 * 10 ^ -6 decimal degrees
* - `a5cm`        - 13: B'1101 0.05m or about 5 * 10 ^ -7 decimal degrees
* - `a2cm`        - 14: B'1110 0.02m or about 2 * 10 ^ -7 decimal degrees
* - `a1cm`        - 15) B'1111 0.01m or about 1 * 10 ^ -7 decimal degrees
* - Encoded as a 4 bit value
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
PositionConfidence ::= ENUMERATED {
   unavailable (0),
   a500m   (1),
   a200m   (2),
   a100m   (3),
   a50m    (4),
   a20m    (5),
   a10m    (6),
   a5m     (7),
   a2m     (8),
   a1m     (9),
   a50cm  (10),
   a20cm  (11),
   a10cm  (12),
   a5cm   (13),
   a2cm   (14),
   a1cm   (15)
 }

/**
* This DE is used in the @ref PrioritizationResponse data frame to indicate the
* general status of a prior prioritization request.
*
* - `unknown`           - 0: Unknown state
* - `requested`         - 1: This prioritization request was detected by the traffic controller
* - `processing`        - 2: Checking request (request is in queue, other requests are prior)
* - `watchOtherTraffic` - 3: Cannot give full permission, therefore watch for other traffic. Note that other requests may be present
* - `granted`           - 4: Intervention was successful and now prioritization is active
* - `rejected`          - 5: The prioritization or preemption request was rejected by the traffic controller
* - `maxPresence`       - 6: The Request has exceeded maxPresence time. Used when the controller has determined that the requester should then back off and request an alternative.
* - `reserviceLocked`   - 7: Prior conditions have resulted in a reservice
*                            locked event: the controller requires the passage of time before another similar request will be accepted
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
PrioritizationResponseStatus ::= ENUMERATED {
  unknown           (0),
  requested         (1),
  processing        (2),
  watchOtherTraffic (3),
  granted           (4),
  rejected          (5),
  maxPresence       (6),
  reserviceLocked   (7),
  ...
}

/**
* This DE is used to provide the R09 priority.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
PriorityLevel ::= INTEGER (0..255)

/**
* This DE provides a means to indicate if a request (found in the Signal RequestMessage) represents
* a new service request, a request update, or a request cancellation for either preemption or priority services.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
PriorityRequestType ::= ENUMERATED {
  priorityRequestTypeReserved (0),
  priorityRequest             (1),
  priorityRequestUpdate       (2),
  priorityCancellation        (3),
  ...
}

/**
* This DE is used to define regions where unique additional content may be added and
* used in the message set. The index values defined below represent various regions known at the time of publication. This
* list is expected to grow over time. The index values assigned here can be augmented by local (uncoordinated)
* assignments in the allowed range. It should be noted that such a local value is specified in the "REGION" ASN module, so
* there is no need to edit the DSRC ASN specification of the standard. This process is further described in Section 11.1.
*
* - `noRegion` - 0: Use default supplied stubs
* - `addGrpA`  - 1: USA
* - `addGrpB`  - 2: Japan
* - `addGrpC`  - 3: EU
*
* @note: new registered regional IDs will be added here
*        The values 128 and above are for local region use
* @category: Infrastructure information
* @revision: V1.3.1
*/
RegionId ::= INTEGER (0..255)
  noRegion     RegionId ::= 0
  addGrpA      RegionId ::= 1
  addGrpB      RegionId ::= 2
  addGrpC      RegionId ::= 3

/**
* This DE is used to provide the R09 reporting point.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
ReportingPoint ::= INTEGER (0..65535)

/**
* This DE is used to provide a unique ID between two parties for various dialog exchanges.
* Combined with the sender's VehicleID (consisting of a TempID or a Station ID), this provides a unique string for some
* mutually defined period of time. A typical example of use would be a signal preemption or priority request dialog
* containing multiple requests from one sender (denoted by the unique RequestID with each). When such a request is
* processed and reflected in the signal status messages, the original sender and the specific request can both be determined.
*
* @note: In typical use, this value is simply incremented in a modulo fashion to ensure a unique stream of values for the
*        device creating it. Any needs for uniqueness across multiple dialogs to one or more parties shall be the responsibility of
*        the device to manage. There are often normative restrictions on the device changing its TempID during various dialogs
*        when this data element is used. Further details of these operational concepts can be found in the relevant standards.
* @category: Infrastructure information
* @revision: V1.3.1
*/
RequestID ::= INTEGER (0..255)

/**
* This DE is used to state what type of signal request is being made to a signal
* controller by a DSRC device in a defined role (such as a police vehicle). The levels of the request typically convey a
* sense of urgency or importance with respect to other demands to allow the controller to use predefined business rules to
* determine how to respond. These rules will vary in terms of how details of overall importance and urgency are to be
* ranked, so they are to be implemented locally. As a result of this regional process, the list below should be assigned well-
* defined meanings by the local deployment. These meaning will typically result in assigning a set of values to list for each
* vehicle role type that is to be supported.
*
* - `requestImportanceLevel1`     1: The least important request
* - `requestImportanceLevel14`   14: The most important request
* - `requestImportanceReserved`  15: Reserved for future use
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RequestImportanceLevel ::= ENUMERATED {
  requestImportanceLevelUnKnown  (0),
  requestImportanceLevel1        (1),
  requestImportanceLevel2        (2),
  requestImportanceLevel3        (3),
  requestImportanceLevel4        (4),
  requestImportanceLevel5        (5),
  requestImportanceLevel6        (6),
  requestImportanceLevel7        (7),
  requestImportanceLevel8        (8),
  requestImportanceLevel9        (9),
  requestImportanceLevel10      (10),
  requestImportanceLevel11      (11),
  requestImportanceLevel12      (12),
  requestImportanceLevel13      (13),
  requestImportanceLevel14      (14),
  requestImportanceReserved     (15)
}

/**
* This DE is used to further define the details of the role which any DSRC device might
* play when making a request to a signal controller. This value is not always needed. For example, perhaps in a
* deployment all police vehicles are to be treated equally. The taxonomy of what details are selected to be entered into the
* list is a regional choice but should be devised to allow the controller to use predefined business rules to respond using the
* data. As another example, perhaps in a regional deployment a cross-city express type of transit vehicle is given a different
* service response for the same request than another type of transit vehicle making an otherwise similar request. As a
* result of this regional process, the list below should be assigned well-defined meanings by the local deployment. These
* meanings will typically result in assigning a set of values to list for each vehicle role type that is to be supported.
*
* - `requestSubRole1`        - 1:  The first type of sub role
* - `requestSubRole14`       - 14: The last type of sub role
* - `requestSubRoleReserved` - 15: Reserved for future use
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RequestSubRole ::= ENUMERATED {
  requestSubRoleUnKnown    (0),
  requestSubRole1          (1),
  requestSubRole2          (2),
  requestSubRole3          (3),
  requestSubRole4          (4),
  requestSubRole5          (5),
  requestSubRole6          (6),
  requestSubRole7          (7),
  requestSubRole8          (8),
  requestSubRole9          (9),
  requestSubRole10        (10),
  requestSubRole11        (11),
  requestSubRole12        (12),
  requestSubRole13        (13),
  requestSubRole14        (14),
  requestSubRoleReserved  (15)
}

/**
* The RestrictionAppliesTo data element provides a short list of common vehicle types which may have one or more
* special movements at an intersection. In general, these movements are not visible to other traffic with signal heads, but
* the SPAT data reflects the state of the movement. Various restricted movements at an intersection can be expressed
* using this element to indicate where the movement applies.
*
* - `none` :              applies to nothing
* - `equippedTransit`:    buses etc.
* - `equippedTaxis`:
* - `equippedOther`:      other vehicle types with necessary signal phase state reception equipment
* - `emissionCompliant`:  regional variants with more definitive items also exist
* - `equippedBicycle`:
* - `weightCompliant`:
* - `heightCompliant`:    Items dealing with traveler needs serviced by the infrastructure. These end users (which are not vehicles) are presumed to be suitably equipped
* - `pedestrians`:
* - `slowMovingPersons`:
* - `wheelchairUsers`:
* - `visualDisabilities`:
* - `audioDisabilities`:  hearing
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RestrictionAppliesTo ::= ENUMERATED {
  none,
  equippedTransit,
  equippedTaxis,
  equippedOther,
  emissionCompliant,
  equippedBicycle,
  weightCompliant,
  heightCompliant,
  pedestrians,
  slowMovingPersons,
  wheelchairUsers,
  visualDisabilities,
  audioDisabilities,
  otherUnknownDisabilities,
  ...
}

/**
* This DE defines an intersection-unique value to convey data about classes of users.
* The mapping used varies with each intersection and is defined in the MAP message if needed. The defined mappings
* found there are used to determine when a given class is meant. The typical use of this element is to map additional
* movement restrictions or rights (in both the MAP and SPAT messages) to special classes of users (trucks, high sided
* vehicles, special vehicles etc.). There is the general presumption that in the absence of this data, any allowed movement
* extends to all users.
*
* An index value to identify data about classes of users the value used varies with each intersection's
* needs and is defined in the map to the assigned classes of supported users.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RestrictionClassID ::= INTEGER (0..255)

/**
* This DE is a 16-bit globally unique identifier assigned to an entity responsible for assigning
* Intersection IDs in the region over which it has such authority. The value zero shall be used for testing, and should only be
* used in the absence of a suitable assignment. A single entity which assigns intersection IDs may be assigned several
* RoadRegulatorIDs. These assignments are presumed to be permanent.
*
* The value zero shall be used for testing only
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RoadRegulatorID ::= INTEGER (0..65535)

/**
* This DE is used to uniquely define a section of roadway within a country or region in a 16-bit field.
* Assignment rules for this value are established elsewhere and may use regional assignment schemas that vary. Within
* the region the policies used to ensure an assigned value’s uniqueness before that value is reused is the responsibility of
* that region. Such reuse is expected to occur, but over somewhat lengthy epoch (months).
*
* The values zero to 255 shall be used for testing only
* Note that the value assigned to an RoadSegment will be
* unique within a given regional ID only during its use
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RoadSegmentID ::= INTEGER (0..65535)

/**
* The RoadwayCrownAngle data element relates the gross tangential angle of the roadway surface with respect to
* the local horizontal axis and is measured at the indicated part of the lane. This measurement is typically made at the
* crown (centerline) or at an edge of the lane path. Its typical use is to relate data used in speed warning and traction
* calculations for the lane segment or roadway segment in which the measurement is taken.
*
* - The value -128 shall be used for unknown
* - The value zero shall be used for angles which are between -0.15 and +0.15
*
* @unit: 0.3 degrees of angle over a range of -38.1 to + 38.1 degrees
* @category: Infrastructure information
* @revision: V1.3.1
*/
RoadwayCrownAngle ::= INTEGER (-128..127)

/**
* This DE is used to provide the R09 route information.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
RouteNumber ::= INTEGER (0..4294967295)

/**
* This DE contains the stream of octets of the actual RTCM message that is being sent.
* The message’s contents are defined in RTCM Standard 10403.1 and in RTCM Standard 10402.1 and its successors.
* Note that most RTCM messages are considerably smaller than the size limit defined here, but that some messages may
* need to be broken into smaller messages (as per the rules defined in the RTCM work) in order to be transmitted over DSRC.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RTCMmessage ::= OCTET STRING (SIZE(1..1023))

/**
* This DE provides the specific revision of the RTCM standard which is being used. This is
* helpful to know precisely the mapping of the message types to their definitions, as well as some minor transport layer
* ordering details when received in the mobile unit. All RTCM SC-104 messages follow a common message numbering
* method (wherein all defined messages are given unique values) which can be decoded from the initial octets of the
* message. This operation is typically performed by the GNSS rover that consumes the messages, so it is transparent at
* the DSRC message set level.
*
* Values:
* - `rtcmRev2`:  Std 10402.x et al
* - `rtcmRev3`:  Std 10403.x et al
*
* @note:: In order to fully support the use of networked transport of RTCM corrections (so-called Ntrip systems), the
*         enumerated list of protocol types provides for all the common types outlined in RTCM Standard 10410.0, Appendix B. It is
*         anticipated that revisions 3.x and 2.3 will predominate in practice as they do today. It should also be noted that RTCM
*         standards use the term `byte` for an 8-bit value, while in this standard the term `octet` is used.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
RTCM-Revision ::= ENUMERATED {
  unknown  (0),
  rtcmRev2 (1),
  rtcmRev3 (2),
  reserved (3),
  ...
}

/**
* A 12-bit signed scaling factor supporting scales from zero (which is not used) to >200%. In this data element, the
* value zero is taken to represent a value of one (scale 1:1). Values above and below this add or remove exactly 0.05%
* from the initial value of 100%. Hence, a value of 2047 adds 102.35% to 100%, resulting in a scale of 202.35% exactly (the
* largest valid scale value). Negative values which would result in an effective final value below zero are not supported. The
* smallest valid value allowed is -1999 and the remaining negative values are reserved for future definition.
*
* @unit: in steps of 0.05 percent
* @category: Infrastructure information
* @revision: V1.3.1
*/
Scale-B12 ::= INTEGER (-2048..2047)

/**
* This DE is an index used to map between the internal state machine of one or more signal controllers (or
* other types of traffic flow devices) and a common numbering system that can represent all possible combinations of active
* states (movements and phases in US traffic terminology). All possible movement variations are assigned a unique value
* within the intersection. Conceptually, the ID represents a means to provide a list of lanes in a set which would otherwise
* need to be enumerated in the message. The values zero and 255 are reserved, so there may up to 254 different signal
* group IDs within one single intersection. The value 255 represents a protected-Movement-Allowed or permissive-
* Movement-Allowed condition that exists at all times. This value is applied to lanes, with or without traffic control devices,
* that operate as free-flow lanes. Typically referred to as Channelized Right/Left Turn Lanes (in right/left-hand drive
* countries).
*
* Values:
* - the value `0` shall be used when the ID is not available or not known
* - the value `255` is reserved to indicate a permanent green movement state
* - therefore a simple 8 phase signal controller device might use 1..9 as its groupIDs
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SignalGroupID ::= INTEGER (0..255)

/**
* This DE is an enumerated list of attributes about the current lane segment which
* may be enabled or disabled to indicate the presence or absence of the selected attribute on the segment. A segment is
* one or more of the straight lines formed between each set of node points. It is common for a segment attribute to persist
* for more than one set of node points if there is any curvature in the lane itself. The described attributes are all binary flags
* in that they do not need to convey any additional data. Other attributes allow sending short data values to reflect a setting
* which is set and persists in a similar fashion.
*
* Various values which can be Enabled and Disabled for a lane segment
* - reserved:
* - doNotBlock: segment where a vehicle may not come to a stop
* - whiteLine:  segment where lane crossing not allowed such as the final few meters of a lane 
* - mergingLaneLeft: indicates porous lanes
* - mergingLaneRight: indicates porous lanes
* - curbOnLeft: indicates presence of curbs
* - curbOnRight: indicates presence of curbs
* - loadingzoneOnLeft:  loading or drop off zones
* - loadingzoneOnRight: loading or drop off zones
* - turnOutPointOnLeft: opening to adjacent street/alley/road
* - turnOutPointOnRight: opening to adjacent street/alley/road
* - adjacentParkingOnLeft: side of road parking
* - adjacentParkingOnRight: side of road parking
* - adjacentBikeLaneOnLeft: presence of marked bike lanes
* - adjacentBikeLaneOnRight: presence of marked bike lanes
* - sharedBikeLane: right of way is shared with bikes who may occupy entire lane width
* - bikeBoxInFront:
* - transitStopOnLeft: any form of bus/transit loading, with pull in-out access to lane on left
* - transitStopOnRight: any form of bus/transit loading, with pull in-out access to lane on right
* - transitStopInLane: any form of bus/transit loading, in mid path of the lane
* - sharedWithTrackedVehicle: lane is shared with train or trolley, not used for crossing tracks 
* - safeIsland: begin/end a safety island in path
* - lowCurbsPresent: for ADA support
* - rumbleStripPresent: for ADA support
* - audibleSignalingPresent: for ADA support
* - adaptiveTimingPresent: for ADA support
* - rfSignalRequestPresent: Supports RF push to walk technologies
* - partialCurbIntrusion: path is blocked by a median or curb but at least 1 meter remains open for use
*                         and at-grade passage Lane geometry details
* - taperToLeft: Used to control final path shape (see standard for defined shapes)
* - taperToRight: Used to control final path shape (see standard for defined shapes)
* - taperToCenterLine: Used to control final path shape (see standard for defined shapes)
* - parallelParking: Parking at an angle with the street
* - headInParking:   Parking at an angle with the street
* - freeParking:     No restriction on use of parking
* - timeRestrictionsOnParking: Parking is not permitted at all times
*                              typically used when the **parking** lane becomes a driving lane at times
* - costToPark: Used where parking has a cost
* - midBlockCurbPresent: a protruding curb near lane edge
* - unEvenPavementPresent: a disjoint height at lane edge
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SegmentAttributeXY ::= ENUMERATED {
  reserved                  ,
  doNotBlock                ,
  whiteLine                 ,
  mergingLaneLeft           ,
  mergingLaneRight          ,
  curbOnLeft                ,
  curbOnRight               ,
  loadingzoneOnLeft         ,
  loadingzoneOnRight        ,
  turnOutPointOnLeft        ,
  turnOutPointOnRight       ,
  adjacentParkingOnLeft     ,
  adjacentParkingOnRight    ,
  adjacentBikeLaneOnLeft    ,
  adjacentBikeLaneOnRight   ,
  sharedBikeLane            ,
  bikeBoxInFront            ,
  transitStopOnLeft         ,
  transitStopOnRight        ,
  transitStopInLane         ,
  sharedWithTrackedVehicle  ,
  safeIsland                ,
  lowCurbsPresent           ,
  rumbleStripPresent        ,
  audibleSignalingPresent   ,
  adaptiveTimingPresent     ,
  rfSignalRequestPresent    ,
  partialCurbIntrusion      ,
  taperToLeft               ,
  taperToRight              ,
  taperToCenterLine         ,
  parallelParking           ,
  headInParking             ,
  freeParking               ,
  timeRestrictionsOnParking ,
  costToPark                ,
  midBlockCurbPresent       ,
  unEvenPavementPresent     ,
  ...
}

/**
* This DE is used to express the radius (length) of the semi-major axis of an
* ellipsoid representing the accuracy which can be expected from a GNSS system in 5cm steps,
* typically at a one sigma level of confidence.
*
* Value is semi-major axis accuracy at one standard dev.
* - Range 0-12.7 meter, LSB = .05m
* - 254 = any value equal or greater than 12.70 meter
* - 255 = unavailable semi-major axis value
*
* @unit: 0.05m
* @category: Infrastructure information
* @revision: V1.3.1
*/
SemiMajorAxisAccuracy ::= INTEGER (0..255)

/**
* This DE is used to orientate the angle of the semi-major axis of an
* ellipsoid representing the accuracy which can be expected from a GNSS system with respect to the coordinate system.
*
* Value is orientation of semi-major axis
* - relative to true north (0-359.9945078786 degrees)
* - LSB units of 360/65535 deg = 0.0054932479
* - a value of 0 shall be 0 degrees
* - a value of 1 shall be 0.0054932479 degrees
* - a value of 65534 shall be 359.9945078786 deg
* - a value of 65535 shall be used for orientation unavailable
*
* @unit: 360/65535 degree
* @category: Infrastructure information
* @revision: V1.3.1
*/
SemiMajorAxisOrientation ::= INTEGER (0..65535)

/**
* This DE is used to express the radius of the semi-minor axis of an ellipsoid
* representing the accuracy which can be expected from a GNSS system in 5cm steps, typically at a one sigma level of
* confidence.
*
* Value is semi-minor axis accuracy at one standard dev
* - range 0-12.7 meter, LSB = .05m
* - 254 = any value equal or greater than 12.70 meter
* - 255 = unavailable semi-minor axis value
*
* @unit: 0.05m
* @category: Infrastructure information
* @revision: V1.3.1
*/
SemiMinorAxisAccuracy ::= INTEGER (0..255)

/**
* This data element represents the recommended velocity of an object, typically a vehicle speed along a roadway,
* expressed in unsigned units of 0.1 meters per second.
*
* - LSB units are 0.1 m/s
* - the value 499 shall be used for values at or greater than 49.9 m/s
* - the value 500 shall be used to indicate that speed is unavailable
*
* @unit: 0.1 m/s
* @category: Infrastructure information
* @revision: V1.3.1
*/
SpeedAdvice ::= INTEGER (0..500)

/**
* This DE is used to provide the 95% confidence level for the currently reported
* value of @ref Speed, taking into account the current calibration and precision of the sensor(s) used to measure and/or
* calculate the value. This data element is only to provide the listener with information on the limitations of the sensing
* system, not to support any type of automatic error correction or to imply a guaranteed maximum error. This data element
* should not be used for fault detection or diagnosis, but if a vehicle is able to detect a fault, the confidence interval should
* be increased accordingly.
*
* - 0 - `unavailable` : Not Equipped or unavailable
* - 1 - `prec100ms`   : 100  meters / sec
* - 2 - `prec10ms`    : 10   meters / sec
* - 3 - `prec5ms`     : 5    meters / sec
* - 4 - `prec1ms`     : 1    meters / sec
* - 5 - `prec0-1ms`   : 0.1  meters / sec
* - 6 - `prec0-05ms`  : 0.05 meters / sec
* - 7 - `prec0-01ms`  : 0.01 meters / sec
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
SpeedConfidenceDSRC ::= ENUMERATED {
   unavailable (0),
   prec100ms   (1),
   prec10ms    (2),
   prec5ms     (3),
   prec1ms     (4),
   prec0-1ms   (5),
   prec0-05ms  (6),
   prec0-01ms  (7)
 }

/**
* This is the 4 octet random device identifier, called the TemporaryID. When used for a mobile OBU device, this value
* will change periodically to ensure the overall anonymity of the vehicle, unlike a typical wireless or wired 802 device ID.
* Because this value is used as a means to identify the local vehicles that are interacting during an encounter, it is used in
* the message set. Other devices, such as infrastructure (RSUs), may have a fixed value for the temporary ID value. See
* also @ref StationId which is used in other deployment regions.
*
* @note: The circumstances and times at which various DSRC devices (notably OBUs) create and change their current
*        Temporary ID is a complex application level topic. It should be noted that the Temporary ID is not the same as a device
*        MAC value, although when used as a means to uniquely identify a device, both have many common properties. It should
*        further be noted that the MAC value for a mobile OBU device (unlike a typical wireless or wired 802 device) will
*        periodically change to a new random value to ensure the overall anonymity of the vehicle.
* @category: Infrastructure information
* @revision: V1.3.1
*/
TemporaryID ::= OCTET STRING (SIZE(4))

/**
* This DE is used to provide the 95% confidence level for the currently reported
* value of DE @ref Throttle, taking into account the current calibration and precision of the sensor(s) used to measure and/or
* calculate the value. This data element is only to provide information on the limitations of the sensing system, not to
* support any type of automatic error correction or to imply a guaranteed maximum error. This data element should not be
* used for fault detection or diagnosis, but if a vehicle is able to detect a fault, the confidence interval should be increased
* accordingly. If a fault that triggers the MIL is of a nature to render throttle performance unreliable, then ThrottleConfidence
* should be represented as "notEquipped."
*
* - 0 - `unavailable`:    B'00 Not Equipped or unavailable
* - 1 - `prec10percent`:  B'01 10 percent Confidence level
* - 2 - `prec1percent`:   B'10 1 percent Confidence level
* - 3 - `prec0-5percent`: B'11 0.5 percent Confidence level
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
ThrottleConfidence ::= ENUMERATED {
   unavailable     (0),
   prec10percent   (1),
   prec1percent    (2),
   prec0-5percent  (3)
 }

/**
* This DE is used to provide the 95% confidence level for the currently reported value
* of time, taking into account the current calibration and precision of the sensor(s) used to measure and/or calculate the
* value. This data element is only to provide information on the limitations of the sensing system, not to support any type of
* automatic error correction or to imply a guaranteed maximum error. This data element should not be used for fault
* detection or diagnosis, but if a vehicle is able to detect a fault, the confidence interval should be increased accordingly.
*
* - 0 - `unavailable`  : Not Equipped or unavailable
* - 1 - `time-100-000` : Better than 100 Seconds
* - 2 - `time-050-000` : Better than 50 Seconds
* - 3 - `time-020-000` : Better than 20 Seconds
* - 4 - `time-010-000` : Better than 10 Seconds
* - 5 - `time-002-000` : Better than 2 Seconds
* - 6 - `time-001-000` : Better than 1 Second
* - 7 - `time-000-500` : Better than 0.5 Seconds
* - 8 - `time-000-200` : Better than 0.2 Seconds
* - 9 - `time-000-100` : Better than 0.1 Seconds
* - 10 - `time-000-050` : Better than 0.05 Seconds
* - 11 - `time-000-020` : Better than 0.02 Seconds
* - 12 - `time-000-010` : Better than 0.01 Seconds
* - 13 - `time-000-005` : Better than 0.005 Seconds
* - 14 - `time-000-002` : Better than 0.001 Seconds
* - 15 - `time-000-001` : Better than 0.001 Seconds
* - 16 - `time-000-000-5` : Better than 0.000,5 Seconds
* - 17 - `time-000-000-2` : Better than 0.000,2 Seconds
* - 18 - `time-000-000-1` : Better than 0.000,1 Seconds
* - 19 - `time-000-000-05` : Better than 0.000,05 Seconds
* - 20 - `time-000-000-02` : Better than 0.000,02 Seconds
* - 21 - `time-000-000-01` : Better than 0.000,01 Seconds
* - 22 - `time-000-000-005` : Better than 0.000,005 Seconds
* - 23 - `time-000-000-002` : Better than 0.000,002 Seconds
* - 24 - `time-000-000-001` : Better than 0.000,001 Seconds
* - 25 - `time-000-000-000-5` : Better than 0.000,000,5 Seconds
* - 26 - `time-000-000-000-2` : Better than 0.000,000,2 Seconds
* - 27 - `time-000-000-000-1` : Better than 0.000,000,1 Seconds
* - 28 - `time-000-000-000-05` : Better than 0.000,000,05 Seconds
* - 29 - `time-000-000-000-02` : Better than 0.000,000,02 Seconds
* - 30 - `time-000-000-000-01` : Better than 0.000,000,01 Seconds
* - 31 - `time-000-000-000-005` : Better than 0.000,000,005 Seconds
* - 32 - `time-000-000-000-002` : Better than 0.000,000,002 Seconds
* - 33 - `time-000-000-000-001` : Better than 0.000,000,001 Seconds
* - 34 - `time-000-000-000-000-5` : Better than 0.000,000,000,5 Seconds
* - 35 - `time-000-000-000-000-2` : Better than 0.000,000,000,2 Seconds
* - 36 - `time-000-000-000-000-1` : Better than 0.000,000,000,1 Seconds
* - 37 - `time-000-000-000-000-05` : Better than 0.000,000,000,05 Seconds
* - 38 - `time-000-000-000-000-02` : Better than 0.000,000,000,02 Seconds
* - 39 - `time-000-000-000-000-01` : Better than 0.000,000,000,01 Seconds
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
TimeConfidence ::= ENUMERATED {
   unavailable              (0),
   time-100-000             (1),
   time-050-000             (2),
   time-020-000             (3),
   time-010-000             (4),
   time-002-000             (5),
   time-001-000             (6),
   time-000-500             (7),
   time-000-200             (8),
   time-000-100             (9),
   time-000-050            (10),
   time-000-020            (11),
   time-000-010            (12),
   time-000-005            (13),
   time-000-002            (14),
   time-000-001            (15),
   time-000-000-5          (16),
   time-000-000-2          (17),
   time-000-000-1          (18),
   time-000-000-05         (19),
   time-000-000-02         (20),
   time-000-000-01         (21),
   time-000-000-005        (22),
   time-000-000-002        (23),
   time-000-000-001        (24),
   time-000-000-000-5      (25),
   time-000-000-000-2      (26),
   time-000-000-000-1      (27),
   time-000-000-000-05     (28),
   time-000-000-000-02     (29),
   time-000-000-000-01     (30),
   time-000-000-000-005    (31),
   time-000-000-000-002    (32),
   time-000-000-000-001    (33),
   time-000-000-000-000-5  (34),
   time-000-000-000-000-2  (35),
   time-000-000-000-000-1  (36),
   time-000-000-000-000-05 (37),
   time-000-000-000-000-02 (38),
   time-000-000-000-000-01 (39)
}

/**
* This is the statistical confidence for the predicted time of signal group state change. For evaluation, the formula
* 10^(x/a)-b with a=82.5 and b=1.3 was used. The values are encoded as probability classes with proposed values listed in
* the below table in the ASN.1 specification.
*
* Value: Probability
* - 0 - 21%
* - 1 - 36%
* - 2 - 47%
* - 3 - 56%
* - 4 - 62%
* - 5 - 68%
* - 6 - 73%
* - 7 - 77%
* - 8 - 81%
* - 9 - 85%
* - 10 - 88%
* - 11 - 91%
* - 12 - 94%
* - 13 - 96%
* - 14 - 98%
* - 15 - 100%
*
* @unit: percent
* @category: Infrastructure information
* @revision: V1.3.1
*/
TimeIntervalConfidence ::= INTEGER (0..15)

/**
* This DE is used to provide the R09 tour information.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
TourNumber ::= INTEGER (0..4294967295)

/**
* This DE is used to provide the R09 train length.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
TrainLength ::= INTEGER (0..7)

/**
* This DE is used to provide the R09 direction information.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
TransitDirection ::= INTEGER (0..255)

/**
*  This DE is used to relate basic level of current ridership.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
TransitVehicleOccupancy ::= ENUMERATED {
  occupancyUnknown    (0),
  occupancyEmpty      (1),
  occupancyVeryLow    (2),
  occupancyLow        (3),
  occupancyMed        (4),
  occupancyHigh       (5),
  occupancyNearlyFull (6),
  occupancyFull       (7)
}

/**
* This DE is used to relate basic information about the transit run in progress. This is
* typically used in a priority request to a signalized system and becomes part of the input processing for how that system
* will respond to the request.
*
* - 0 - `loading`:     parking and unable to move at this time
* - 1 - `anADAuse`:    an ADA access is in progress (wheelchairs, kneeling, etc.)
* - 2 - `aBikeLoad`:   loading of a bicycle is in progress
* - 3 - `doorOpen`:    a vehicle door is open for passenger access
* - 4 - `charging`:    a vehicle is connected to charging point
* - 5 - `atStopLine`:  a vehicle is at the stop line for the lane it is in
*
* @note: Most of these values are used to detect that the transit vehicle in not in a state where movement can occur
* (and that therefore any priority signal should be ignored until the vehicle is again ready to depart).
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
TransitVehicleStatus ::= BIT STRING {
  loading     (0),
  anADAuse    (1),
  aBikeLoad   (2),
  doorOpen    (3),
  charging    (4),
  atStopLine  (5)
} (SIZE(8))

/**
* This DE is used to provide the current state of the vehicle transmission.
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
TransmissionState ::= ENUMERATED {
  neutral      (0),
  park         (1),
  forwardGears (2),
  reverseGears (3),
  reserved1    (4),
  reserved2    (5),
  reserved3    (6),
  unavailable  (7)
}

/**
* The height of the vehicle, measured from the ground to the highest surface, excluding any antenna(s), and
* expressed in units of 5 cm. In cases of vehicles with adjustable ride heights, camper shells, and other devices which may
* cause the overall height to vary, the largest possible height will be used.
*
* Value is the height of the vehicle, LSB units of 5 cm, range to 6.35 meters
*
* @unit: 5cm
* @category: Infrastructure information
* @revision: V1.3.1
*/
VehicleHeight ::= INTEGER (0..127)

/**
* This DE is a type list (i.e., a classification list) of the vehicle in terms of overall size. The
* data element entries follow the definitions defined in the US DOT Highway Performance Monitoring System (HPMS).
* Many infrastructure roadway operators collect and classify data according to this list for regulatory reporting needs.
* Within the ITS industry and within the DSRC message set standards work, there are many similar lists of types for
* overlapping needs and uses.
*
* - 0 - `none`:       Not Equipped, Not known or unavailable
* - 1 - `unknown`:    Does not fit any other category
* - 2 - `special`:    Special use
* - 3 - `moto`:       Motorcycle
* - 4 - `car`:        Passenger car
* - 5 - `carOther`:   Four tire single units
* - 6 - `bus`:        Buses
* - 7 - `axleCnt2`:   Two axle, six tire single units
* - 8 - `axleCnt3`:   Three axle, single units
* - 9 - `axleCnt4`:   Four or more axle, single unit
* - 10 - `axleCnt4Trailer`:        Four or less axle, single trailer
* - 11 - `axleCnt5Trailer`:        Five or less axle, single trailer
* - 12 - `axleCnt6Trailer`:        Six or more axle, single trailer
* - 13 - `axleCnt5MultiTrailer`:   Five or less axle, multi-trailer
* - 14 - `axleCnt6MultiTrailer`:   Six axle, multi-trailer
* - 15 - `axleCnt7MultiTrailer`:   Seven or more axle, multi-trailer
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
VehicleType ::= ENUMERATED {
  none                 (0),
  unknown              (1),
  special              (2),
  moto                 (3),
  car                  (4),
  carOther             (5),
  bus                  (6),
  axleCnt2             (7),
  axleCnt3             (8),
  axleCnt4             (9),
  axleCnt4Trailer      (10),
  axleCnt5Trailer      (11),
  axleCnt6Trailer      (12),
  axleCnt5MultiTrailer (13),
  axleCnt6MultiTrailer (14),
  axleCnt7MultiTrailer (15),
  ...
}

/**
* This DE represents the velocity of an object, typically a vehicle speed or the recommended speed of
* travel along a roadway, expressed in unsigned units of 0.02 meters per second. When used with motor vehicles it may be
* combined with the transmission state to form a data frame for use. A value of 8191 shall be used when the speed is
* unavailable. Note that Velocity as used here is intended to be a scalar value and not a vector.
*
* The value 8191 indicates that velocity is unavailable
*
* @unit: 0.02 m/s
* @category: Infrastructure information
* @revision: V1.3.1
*/
Velocity ::= INTEGER (0..8191)

/**
* This DE is used to provide the R09 version information.
*
* @category: Infrastructure information
* @revision: V2.2.1
*/
VersionId ::= INTEGER (0..4294967295)

/**
* This DE is used to indicate to the vehicle that it must stop at the stop line and not move past.
*
* If "true", the vehicles on this specific connecting maneuver have to stop on the stop-line and not to enter the collision area
*
* @category: Infrastructure information
* @revision: V1.3.1
*/
WaitOnStopline ::= BOOLEAN

/**
* This DE is used to provide an estimated distance from the stop bar, along the lane
* centerline back in the lane to which it pertains. It is used in various ways to relate this distance value. When used with
* clearance zones, it represents the point at which the driver can successfully execute the connection maneuver. It is used
* in the Clearance Maneuver Assist data frame to relate dynamic data about the lane. It is also used to relate the distance
* from the stop bar to the rear edge of any queue. It is further used within the context of a vehicle's traveling speed to
* advise on preferred dynamic approach speeds.
*
* 0 = unknown,
* The value 10000 to be used for Distances >=10000 m (e.g. from known point to another point along a
* known path, often against traffic flow direction when used for measuring queues)
*
* @unit: meter
* @category: Infrastructure information
* @revision: V1.3.1
*/
ZoneLength ::= INTEGER (0..10000)

/** 
* ## References:
* 1. [ISO TS 19091]: "Intelligent transport systems - Cooperative ITS - Using V2I and I2V communications for applications related to signalized intersections".
* 2. [SAE J2735]: "SURFACE VEHICLE STANDARD - V2X Communications Message Set Dictionary"
* 3. [OCIT]: "OCIT Developer Group. https://ocit.org"
*/

END
"""