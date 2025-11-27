import unittest
from unittest.mock import MagicMock, patch


from flexstack.facilities.ca_basic_service.cam_transmission_management import GenerationDeltaTime, CAMTransmissionManagement, CooperativeAwarenessMessage, VehicleData
from flexstack.facilities.ca_basic_service.cam_coder import CAMCoder


class TestGenerationDeltaTime(unittest.TestCase):

    def test_set_in_normal_timestamp(self):
        timestamp = 1675871599
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        self.assertEqual(generation_delta_time.msec,
                         (((timestamp*1000)-1072915200000+5000) % 65536))

    def test_as_timestamp_in_certain_point(self):
        timestamp = 1755763553.722
        reception_timestamp_millis = (timestamp+0.3)*1000
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        self.assertEqual(generation_delta_time.as_timestamp_in_certain_point(
            reception_timestamp_millis), timestamp*1000)

    def test__gt__(self):
        timestamp = 1675871599
        timestamp2 = timestamp + 1
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        generation_delta_time2 = GenerationDeltaTime.from_timestamp(timestamp2)
        self.assertTrue(generation_delta_time2 > generation_delta_time)
        self.assertFalse(generation_delta_time > generation_delta_time2)

    def test__lt__(self):
        timestamp = 1675871599
        timestamp2 = timestamp + 1
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        generation_delta_time2 = GenerationDeltaTime.from_timestamp(timestamp2)
        self.assertTrue(generation_delta_time < generation_delta_time2)
        self.assertFalse(generation_delta_time2 < generation_delta_time)

    def test__ge__(self):
        timestamp = 1675871599
        timestamp2 = timestamp + 1
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        generation_delta_time2 = GenerationDeltaTime.from_timestamp(timestamp2)
        self.assertTrue(generation_delta_time >= generation_delta_time)
        self.assertTrue(generation_delta_time2 >= generation_delta_time)
        self.assertFalse(generation_delta_time >= generation_delta_time2)

    def test__le__(self):
        timestamp = 1675871599
        timestamp2 = timestamp + 1
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        generation_delta_time2 = GenerationDeltaTime.from_timestamp(timestamp2)
        self.assertTrue(generation_delta_time <= generation_delta_time)
        self.assertTrue(generation_delta_time <= generation_delta_time2)
        self.assertFalse(generation_delta_time2 <= generation_delta_time)

    def test__add__(self):
        timestamp = 1675871599
        generation_delta_time = GenerationDeltaTime.from_timestamp(timestamp)
        generation_delta_time2 = GenerationDeltaTime(msec=30)
        sum = generation_delta_time + generation_delta_time2
        self.assertEqual(sum, (generation_delta_time.msec+30) % 65536)

    def test__sub__(self):
        generation_delta_time = GenerationDeltaTime(msec=20)
        generation_delta_time2 = GenerationDeltaTime(msec=30)
        diff = generation_delta_time - generation_delta_time2
        self.assertEqual(diff, -10+65536)


class TestCooperativeAwarenessMessage(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.coder = CAMCoder()

    def test__init__(self):
        cooperative_awareness_message = CooperativeAwarenessMessage()
        encoded_white = self.coder.encode(cooperative_awareness_message.cam)
        expected_cam = b'\x02\x02\x00\x00\x00\x00\x00\x00\x00\ri:@:\xd2t\x80?\xff\xff\xfc#\xb7t>\x00\xe1\x1f\xdf\xff\xfe\xbf\xe9\xed\x077\xfe\xeb\xff\xf6\x00'
        self.assertEqual(encoded_white, expected_cam)

    def test_fullfill_with_vehicle_data(self):
        vehicle_data = VehicleData(
            station_id=30,
            station_type=5,
            drive_direction='forward',
            vehicle_length={"vehicleLengthValue": 50,
                            "vehicleLengthConfidenceIndication": "unavailable"},
            vehicle_width=30
        )

        cooperative_awareness_message = CooperativeAwarenessMessage()
        cooperative_awareness_message.fullfill_with_vehicle_data(vehicle_data)
        self.assertEqual(
            cooperative_awareness_message.cam['header']['stationId'], vehicle_data.station_id)
        self.assertEqual(cooperative_awareness_message.cam['cam']['camParameters']
                         ['basicContainer']['stationType'], vehicle_data.station_type)
        self.assertEqual(cooperative_awareness_message.cam['cam']['camParameters']
                         ['highFrequencyContainer'][1]['driveDirection'], vehicle_data.drive_direction)
        self.assertEqual(cooperative_awareness_message.cam['cam']['camParameters']['highFrequencyContainer']
                         [1]['vehicleLength']['vehicleLengthValue'], vehicle_data.vehicle_length["vehicleLengthValue"])
        self.assertEqual(cooperative_awareness_message.cam['cam']['camParameters']
                         ['highFrequencyContainer'][1]['vehicleWidth'], vehicle_data.vehicle_width)

    def test_fullfill_with_tpv_data(self):
        tpv_data = {"class": "TPV", "device": "/dev/ttyACM0", "mode": 3, "time": "2020-03-13T13:01:14.000Z", "ept": 0.005, "lat": 41.453606167,
                    "lon": 2.073707333, "alt": 163.500, "epx": 8.754, "epy": 10.597, "epv": 31.970, "track": 0.0000, "speed": 0.011, "climb": 0.000, "eps": 0.57}
        cooperative_awareness_message = CooperativeAwarenessMessage()
        cooperative_awareness_message.fullfill_with_tpv_data(tpv_data)
        self.assertEqual(
            cooperative_awareness_message.cam['cam']['generationDeltaTime'], 24856)
        self.assertEqual(cooperative_awareness_message.cam['cam']['camParameters']
                         ['basicContainer']['referencePosition']['latitude'], int(tpv_data['lat']*10000000))
        self.assertEqual(cooperative_awareness_message.cam['cam']['camParameters']
                         ['basicContainer']['referencePosition']['longitude'], int(tpv_data['lon']*10000000))


class TestCamTransmissionManagement(unittest.TestCase):

    def test_location_service_callback(self):
        """
        Tests the location service callback.

        Mocks the call to fullfill_with_tpv_data and checks that the method is called with the correct parameters.
        Mocks the call to send_next_cam and checks that the method is called with the correct parameters.
        """
        btp_router = MagicMock()
        cam_coder = MagicMock()
        ca_basic_service_ldm = MagicMock()
        ca_basic_service_ldm.add_provider_data_to_ldm = MagicMock()
        vehicle_data = VehicleData(
            station_id=30,
            station_type=5,
            drive_direction='forward',
            vehicle_length={"vehicleLengthValue": 50,
                            "vehicleLengthConfidenceIndication": "unavailable"},
            vehicle_width=30
        )
        tpv_data = {"class": "TPV", "device": "/dev/ttyACM0", "mode": 3, "time": "2020-03-13T13:01:14.000Z", "ept": 0.005, "lat": 41.453606167,
                    "lon": 2.073707333, "alt": 163.500, "epx": 8.754, "epy": 10.597, "epv": 31.970, "track": 0.0000, "speed": 0.011, "climb": 0.000, "eps": 0.57}
        cam_transmission_management = CAMTransmissionManagement(
            btp_router, cam_coder, vehicle_data, ca_basic_service_ldm, )
        self.assertIsNone(cam_transmission_management.last_cam_sent)
        
        with patch.object(CooperativeAwarenessMessage, 'fullfill_with_tpv_data') as mock_fullfill:
            cam_transmission_management.send_next_cam = MagicMock()
            cam_transmission_management.location_service_callback(tpv_data)
            mock_fullfill.assert_called_with(tpv_data)
            cam_transmission_management.send_next_cam.assert_called_with()

    def test_send_next_cam(self):
        btp_router = MagicMock()
        btp_router.btp_data_request = MagicMock()
        cam_coder = MagicMock()
        cam_coder.encode = MagicMock(
            return_value=b'\x02\x02\x00\x00\x00\x00\x00\x00\x00\ri:@:\xd2t\x80?\xff\xff\xfc#\xb7t>\x00\xe1\x1f\xdf\xff\xfe\xbf\xe9\xed\x077\xfe\xeb\xff\xf6\x00')
        vehicle_data = VehicleData(
            station_id=30,
            station_type=5,
            drive_direction='forward',
            vehicle_length={"vehicleLengthValue": 50,
                            "vehicleLengthConfidenceIndication": "unavailable"},
            vehicle_width=30
        )
        cam_transmission_management = CAMTransmissionManagement(
            btp_router, cam_coder, vehicle_data)
        cam_transmission_management.send_next_cam()
        btp_router.btp_data_request.assert_called()
        cam_coder.encode.assert_called_with(
            cam_transmission_management.current_cam_to_send.cam)


if __name__ == '__main__':
    unittest.main()
