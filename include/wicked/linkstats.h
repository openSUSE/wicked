/*
 * Interface statistics for netinfo library
 *
 * Copyright (C) 2012 Olaf Kirch <okir@suse.de>
 */

#ifndef __WICKED_LINKSTATS_H__
#define __WICKED_LINKSTATS_H__

struct ni_link_stats {
	uint64_t		rx_packets;		/* total packets received	*/
	uint64_t		tx_packets;		/* total packets transmitted	*/
	uint64_t		rx_bytes;		/* total bytes received 	*/
	uint64_t		tx_bytes;		/* total bytes transmitted	*/
	uint64_t		rx_errors;		/* bad packets received		*/
	uint64_t		tx_errors;		/* packet transmit problems	*/
	uint64_t		rx_dropped;		/* no space in linux buffers	*/
	uint64_t		tx_dropped;		/* no space available in linux	*/
	uint64_t		multicast;		/* multicast packets received	*/
	uint64_t		collisions;

	/* detailed rx_errors: */
	uint64_t		rx_length_errors;
	uint64_t		rx_over_errors;		/* receiver ring buff overflow	*/
	uint64_t		rx_crc_errors;		/* recved pkt with crc error	*/
	uint64_t		rx_frame_errors;	/* recv'd frame alignment error */
	uint64_t		rx_fifo_errors;		/* recv'r fifo overrun		*/
	uint64_t		rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	uint64_t		tx_aborted_errors;
	uint64_t		tx_carrier_errors;
	uint64_t		tx_fifo_errors;
	uint64_t		tx_heartbeat_errors;
	uint64_t		tx_window_errors;

	/* for cslip etc */
	uint64_t		rx_compressed;
	uint64_t		tx_compressed;
};

#endif /* __WICKED_LINKSTATS_H__ */
