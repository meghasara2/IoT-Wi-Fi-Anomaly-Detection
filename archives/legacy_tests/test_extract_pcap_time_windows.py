"""
Unit tests for the experimental fixed 1-second PCAP feature extractor.

Tests cover:
1. Dense burst capping (e.g. 10 packets arriving within microseconds -> packet_rate = 10.0, not millions)
2. Single-packet window conventions (packet_rate = 1.0, mean_IAT = NaN, IAT_std = NaN, packet_size_std = 0.0)
3. Two-packet window conventions (IAT_std = 0.0, sample std for packet_size)
4. Duplicate timestamp handling (Delta t = 0 preserved without division error)
5. Exact window boundaries ([start, end) half-open intervals)
6. Sparse output (default) vs continuous/empty bin inclusion (--include-empty)
7. Multi-client separation (traffic attributed to correct client MACs without cross-contamination)
8. CLI and pipeline validation (column validation, ordering, refuse overwrite)
"""

import math
import os
import shutil
import tempfile
import unittest
import pandas as pd
import numpy as np

from src.extract_pcap_time_windows import (
    compute_1s_features_for_client,
    extract_1s_features_from_dataframe,
    run_1s_extraction_pipeline,
    validate_raw_frame_records
)


class TestExtractPcapTimeWindows(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_dense_burst_rate_capping(self):
        """
        Verify that 10 packets arriving within 2 microseconds in a single 1-second bin
        yield packet_rate = 10.0 (packets captured per 1-second bin), not 4.19M pkts/sec.
        """
        base_time = 1774787968.0
        # 10 packets separated by ~0.2 microseconds
        timestamps = [base_time + 0.1 + (i * 0.0000002) for i in range(10)]
        sizes = [66] * 10
        frame_numbers = list(range(1, 11))

        df_burst = pd.DataFrame({
            'frame_number': frame_numbers,
            'timestamp': timestamps,
            'packet_size': sizes,
            'client_mac': ['00:11:22:33:44:55'] * 10
        })

        features_df = compute_1s_features_for_client('00:11:22:33:44:55', df_burst, include_empty=False)

        self.assertEqual(len(features_df), 1)
        row = features_df.iloc[0]

        # 10 packets captured in this 1s bin -> rate must be 10.0
        self.assertEqual(row['packet_count'], 10)
        self.assertEqual(row['packet_rate'], 10.0)
        self.assertAlmostEqual(row['mean_packet_size'], 66.0, places=4)
        self.assertAlmostEqual(row['packet_size_std'], 0.0, places=4)

        # IAT should be approximately 0.0000002 seconds
        self.assertAlmostEqual(row['mean_IAT'], 0.0000002, places=6)
        self.assertFalse(math.isnan(row['mean_IAT']))

    def test_single_packet_window_conventions(self):
        """
        For N=1:
        - packet_count = 1
        - packet_rate = 1.0
        - mean_packet_size = size
        - packet_size_std = 0.0
        - mean_IAT = NaN (insufficient samples, no intervals)
        - IAT_std = NaN
        """
        df_single = pd.DataFrame({
            'frame_number': [101],
            'timestamp': [1774787968.45],
            'packet_size': [128],
            'client_mac': ['00:11:22:33:44:55']
        })

        features_df = compute_1s_features_for_client('00:11:22:33:44:55', df_single, include_empty=False)

        self.assertEqual(len(features_df), 1)
        row = features_df.iloc[0]

        self.assertEqual(row['packet_count'], 1)
        self.assertEqual(row['packet_rate'], 1.0)
        self.assertEqual(row['mean_packet_size'], 128.0)
        self.assertEqual(row['packet_size_std'], 0.0)
        self.assertTrue(math.isnan(row['mean_IAT']))
        self.assertTrue(math.isnan(row['IAT_std']))

    def test_two_packet_window_conventions(self):
        """
        For N=2:
        - packet_count = 2
        - packet_rate = 2.0
        - mean_IAT = Delta t
        - IAT_std = 0.0 (single interval, zero dispersion)
        - packet_size_std = sample std dev
        """
        df_two = pd.DataFrame({
            'frame_number': [1, 2],
            'timestamp': [1774787968.10, 1774787968.40],
            'packet_size': [100, 200],
            'client_mac': ['00:11:22:33:44:55', '00:11:22:33:44:55']
        })

        features_df = compute_1s_features_for_client('00:11:22:33:44:55', df_two, include_empty=False)

        self.assertEqual(len(features_df), 1)
        row = features_df.iloc[0]

        self.assertEqual(row['packet_count'], 2)
        self.assertEqual(row['packet_rate'], 2.0)
        self.assertAlmostEqual(row['mean_IAT'], 0.30, places=5)
        self.assertEqual(row['IAT_std'], 0.0)
        self.assertEqual(row['mean_packet_size'], 150.0)
        # sample std dev of [100, 200] with ddof=1 is sqrt((50^2 + 50^2)/1) = sqrt(5000) ~ 70.710678
        self.assertAlmostEqual(row['packet_size_std'], math.sqrt(5000), places=4)

    def test_duplicate_timestamps(self):
        """
        Duplicate capture timestamps (Delta t = 0) must be preserved in consecutive differences
        without division-by-zero errors or crash.
        """
        df_dup = pd.DataFrame({
            'frame_number': [1, 2, 3],
            'timestamp': [1774787968.20, 1774787968.20, 1774787968.50],
            'packet_size': [60, 60, 60],
            'client_mac': ['00:11:22:33:44:55'] * 3
        })

        features_df = compute_1s_features_for_client('00:11:22:33:44:55', df_dup, include_empty=False)

        self.assertEqual(len(features_df), 1)
        row = features_df.iloc[0]

        self.assertEqual(row['packet_count'], 3)
        self.assertEqual(row['packet_rate'], 3.0)
        # diffs: [0.0, 0.30] -> mean = 0.15
        self.assertAlmostEqual(row['mean_IAT'], 0.15, places=5)
        # sample std of [0.0, 0.30]: diffs from mean 0.15 are -0.15 and +0.15 -> sqrt((0.0225 + 0.0225)/1) ~ 0.212132
        self.assertAlmostEqual(row['IAT_std'], math.sqrt(0.045), places=4)

    def test_window_boundaries(self):
        """
        Verify half-open interval [start, end) handling:
        Packet at 1774787968.999 is in bin 1774787968.
        Packet at 1774787969.000 is in bin 1774787969.
        """
        df_boundary = pd.DataFrame({
            'frame_number': [1, 2],
            'timestamp': [1774787968.999, 1774787969.000],
            'packet_size': [100, 100],
            'client_mac': ['00:11:22:33:44:55', '00:11:22:33:44:55']
        })

        features_df = compute_1s_features_for_client('00:11:22:33:44:55', df_boundary, include_empty=False)

        self.assertEqual(len(features_df), 2)
        row0 = features_df.iloc[0]
        row1 = features_df.iloc[1]

        self.assertEqual(row0['bin_start_timestamp'], 1774787968.0)
        self.assertEqual(row0['bin_end_timestamp'], 1774787969.0)
        self.assertEqual(row0['packet_count'], 1)

        self.assertEqual(row1['bin_start_timestamp'], 1774787969.0)
        self.assertEqual(row1['bin_end_timestamp'], 1774787970.0)
        self.assertEqual(row1['packet_count'], 1)

    def test_sparse_vs_include_empty(self):
        """
        Test that empty intermediate 1-second bins are omitted by default (sparse),
        and included with documented NaN/0 conventions when include_empty=True.
        """
        df_gap = pd.DataFrame({
            'frame_number': [1, 2],
            'timestamp': [1774787968.1, 1774787971.2],
            'packet_size': [100, 200],
            'client_mac': ['AA:BB:CC:DD:EE:FF', 'AA:BB:CC:DD:EE:FF']
        })

        # 1. Sparse default
        sparse_df = compute_1s_features_for_client('AA:BB:CC:DD:EE:FF', df_gap, include_empty=False)
        self.assertEqual(len(sparse_df), 2)
        self.assertEqual(list(sparse_df['bin_start_timestamp']), [1774787968.0, 1774787971.0])

        # 2. Include empty
        full_df = compute_1s_features_for_client('AA:BB:CC:DD:EE:FF', df_gap, include_empty=True)
        # Bins: 1774787968, 1774787969, 1774787970, 1774787971 -> 4 bins
        self.assertEqual(len(full_df), 4)

        empty_row1 = full_df.iloc[1]  # Bin 1774787969
        self.assertEqual(empty_row1['bin_start_timestamp'], 1774787969.0)
        self.assertEqual(empty_row1['packet_count'], 0)
        self.assertEqual(empty_row1['packet_rate'], 0.0)
        self.assertTrue(math.isnan(empty_row1['mean_packet_size']))
        self.assertTrue(math.isnan(empty_row1['packet_size_std']))
        self.assertTrue(math.isnan(empty_row1['mean_IAT']))
        self.assertTrue(math.isnan(empty_row1['IAT_std']))

    def test_multiple_clients(self):
        """
        Verify that multiple clients are grouped separately and their time windows do not leak.
        """
        df_multi = pd.DataFrame({
            'frame_number': [1, 2, 3, 4],
            'timestamp': [1774787968.1, 1774787968.2, 1774787968.3, 1774787968.4],
            'packet_size': [50, 60, 70, 80],
            'client_mac': ['11:11:11:11:11:11', '22:22:22:22:22:22', '11:11:11:11:11:11', '22:22:22:22:22:22']
        })

        features_df = extract_1s_features_from_dataframe(df_multi, include_empty=False)

        self.assertEqual(len(features_df), 2)
        c1_row = features_df[features_df['client_mac'] == '11:11:11:11:11:11'].iloc[0]
        c2_row = features_df[features_df['client_mac'] == '22:22:22:22:22:22'].iloc[0]

        self.assertEqual(c1_row['packet_count'], 2)
        self.assertEqual(c1_row['mean_packet_size'], 60.0)  # (50+70)/2

        self.assertEqual(c2_row['packet_count'], 2)
        self.assertEqual(c2_row['mean_packet_size'], 70.0)  # (60+80)/2

    def test_validation_invalid_packet_length(self):
        """
        Verify validate_raw_frame_records rejects negative or zero packet lengths.
        """
        df_invalid = pd.DataFrame({
            'frame_number': [1],
            'timestamp': [1774787968.1],
            'packet_size': [-5],
            'client_mac': ['00:11:22:33:44:55']
        })
        with self.assertRaises(ValueError):
            validate_raw_frame_records(df_invalid)

    def test_validation_unordered_timestamps(self):
        """
        Verify compute_1s_features_for_client correctly handles frames sorted by (timestamp, frame_number).
        """
        # Out-of-order input
        df_unordered = pd.DataFrame({
            'frame_number': [2, 1],
            'timestamp': [1774787968.5, 1774787968.1],
            'packet_size': [100, 50],
            'client_mac': ['00:11:22:33:44:55', '00:11:22:33:44:55']
        })

        features_df = compute_1s_features_for_client('00:11:22:33:44:55', df_unordered, include_empty=False)
        self.assertEqual(len(features_df), 1)
        row = features_df.iloc[0]
        # Diff should be 0.4, not negative -0.4
        self.assertAlmostEqual(row['mean_IAT'], 0.4, places=5)

    def test_pipeline_refuses_overwrite(self):
        """
        Verify run_1s_extraction_pipeline refuses to overwrite existing output files without overwrite=True.
        """
        dummy_features_path = os.path.join(self.test_dir, "test_features.csv")
        dummy_summary_path = os.path.join(self.test_dir, "test_summary.csv")

        # Create dummy file
        with open(dummy_features_path, "w") as f:
            f.write("existing")

        with self.assertRaises(FileExistsError):
            run_1s_extraction_pipeline(
                pcap_path="non_existent.pcapng",
                output_features_path=dummy_features_path,
                output_summary_path=dummy_summary_path,
                overwrite=False
            )


if __name__ == '__main__':
    unittest.main()
