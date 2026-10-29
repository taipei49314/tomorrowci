"""Focused PCM regression checks; these are not Pydub's complete upstream suite.

Run unchanged before/after the dependency fix. Import inside each test so an
import regression remains a real test error with the same selected test IDs.
No ffmpeg, audio devices, files from the user, or network are required.
"""
import io
import struct
import unittest


def segment(samples=(1000, -1000, 2000, -2000), rate=8000):
    from pydub import AudioSegment
    return AudioSegment(struct.pack('<' + 'h' * len(samples), *samples),
                        sample_width=2, frame_rate=rate, channels=1)


class AudioopCompatibility(unittest.TestCase):
    def test_silence_and_rms(self):
        from pydub import AudioSegment
        audio = AudioSegment.silent(duration=100, frame_rate=8000)
        self.assertEqual(len(audio), 100)
        self.assertEqual(audio.rms, 0)
        self.assertEqual(segment((1000, -1000)).rms, 1000)

    def test_gain_preserves_and_attenuates_pcm(self):
        audio = segment()
        self.assertEqual(audio.apply_gain(0).raw_data, audio.raw_data)
        self.assertLess(audio.apply_gain(-6).rms, audio.rms)
        self.assertGreater(audio.apply_gain(-6).rms, 0)

    def test_gain_clips_signed_samples(self):
        self.assertEqual(list(segment((30000, -30000)).apply_gain(20).get_array_of_samples()),
                         [32767, -32768])

    def test_channel_round_trip(self):
        audio = segment()
        stereo = audio.set_channels(2)
        self.assertEqual(stereo.channels, 2)
        self.assertEqual(list(stereo.get_array_of_samples()),
                         [1000, 1000, -1000, -1000, 2000, 2000, -2000, -2000])
        self.assertEqual(stereo.set_channels(1).raw_data, audio.raw_data)

    def test_reverse_samples(self):
        self.assertEqual(list(segment().reverse().get_array_of_samples()),
                         [-2000, 2000, -1000, 1000])

    def test_wav_round_trip(self):
        from pydub import AudioSegment
        audio = segment()
        output = io.BytesIO()
        audio.export(output, format='wav')
        output.seek(0)
        restored = AudioSegment.from_file(output, format='wav')
        self.assertEqual(restored.raw_data, audio.raw_data)
        self.assertEqual(restored.frame_rate, 8000)
        self.assertEqual(restored.channels, 1)

    def test_resampling_preserves_duration(self):
        audio = segment((1000, -1000) * 400)
        resampled = audio.set_frame_rate(16000)
        self.assertEqual(resampled.frame_rate, 16000)
        self.assertLessEqual(abs(len(resampled) - len(audio)), 1)
        self.assertGreater(resampled.rms, 0)

    def test_sample_width_round_trip(self):
        audio = segment()
        self.assertEqual(audio.set_sample_width(4).set_sample_width(2).raw_data, audio.raw_data)


if __name__ == '__main__':
    unittest.main(verbosity=2)
