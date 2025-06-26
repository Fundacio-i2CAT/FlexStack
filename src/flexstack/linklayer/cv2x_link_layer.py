from __future__ import annotations
from collections.abc import Callable
import multiprocessing
import threading

# pylint: disable=import-error
from .cv2xlinklayer import CV2XLinkLayer
from .link_layer import LinkLayer


class PythonCV2XLinkLayer(LinkLayer):
    """
    Link Layer to directly send via C-V2X. Uses the Telematics SDK from Qualcomm.
    This link Layer requires the usage of a pre-compiled library.

    Attributes
    ----------
    receive_callback : Callable[[bytes], None]
        Callback to call when a packet is received.
    link_layer : CV2XLinkLayer
        Link Layer to send and receive C-V2X messages.
    process : multiprocessing.Process
        Process to run the receive function.
    callback_thread : threading.Thread
        Thread to handle callbacks in the main memory space.
    callback_queue : multiprocessing.Queue
        Queue for transferring data between processes for callback execution.
    stop_event : multiprocessing.Event
        Event to signal the process to stop.
    """

    def __init__(self, receive_callback: Callable[[bytes], None]) -> None:
        super().__init__(receive_callback)
        self.link_layer = CV2XLinkLayer()
        self.stop_event = multiprocessing.Event()
        self.callback_queue = multiprocessing.Queue()

        # Process for receiving data
        self.process = multiprocessing.Process(
            target=self.receive_process,
            args=(self.callback_queue, self.stop_event),
            daemon=True,
        )
        self.process.start()

        # Thread for handling callbacks in the main process
        self.callback_thread = threading.Thread(
            target=self.callback_handler_loop, args=(self.callback_queue,), daemon=True
        )
        self.callback_thread.start()

    def send(self, packet: bytes) -> None:
        """
        Sends a packet via C-V2X.

        Parameters
        ----------
        packet : bytes
            Packet to send.
        """
        self.link_layer.send(b"\x03" + packet)

    def receive_process(
        self, callback_queue: multiprocessing.Queue, stop_event: multiprocessing.Event
    ) -> None:
        """
        Process to receive data from CV2XLinkLayer and place it in the callback queue.

        Parameters
        ----------
        callback_queue : multiprocessing.Queue
            Queue for transferring received data to the main process.
        stop_event : multiprocessing.Event
            Event to signal the process to stop.
        """
        while not stop_event.is_set():
            data = self.link_layer.receive()
            if data:
                data = data[1:]  # Remove the first byte as per protocol
                callback_queue.put(data)  # Place data in the queue

    def callback_handler_loop(self, callback_queue: multiprocessing.Queue) -> None:
        """
        Thread loop to handle callbacks from the callback queue.

        Parameters
        ----------
        callback_queue : multiprocessing.Queue
            Queue for transferring received data to the main process.
        """
        while True:
            data = callback_queue.get()
            if data is None:  # Stop signal
                break
            if self.receive_callback:
                self.receive_callback(data)

    def stop(self) -> None:
        """
        Stops the receive process, callback thread, and cleans up resources.
        """
        # Signal the process to stop
        self.stop_event.set()
        self.process.join()

        # Stop the callback thread
        self.callback_queue.put(None)  # Send a stop signal to the thread
        self.callback_thread.join()
