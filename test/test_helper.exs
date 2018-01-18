ExUnit.start()

defmodule PDFConstants do
  def from_hex(s),
    do:
      s |> String.split(~r/[\s:]+/i, trim: true) |> Enum.map(fn n -> Integer.parse(n, 16) end)
      |> Enum.reduce(<<>>, fn {i, ""}, acc -> acc <> <<i>> end)

  def ask,
    do:
      from_hex("""
       77 07 6d 0a 73 18 a5 7d
       3c 16 c1 72 51 b2 66 45
       df 4c 2f 87 eb c0 99 2a
       b1 77 fb a5 1d b9 2c 2a
      """)

  def apk,
    do:
      from_hex("""
       85 20 f0 09 89 30 a7 54
       74 8b 7d dc b4 3e f7 5a
       0d bf 3a 0d 26 38 1a f4
       eb a4 a9 8e aa 9b 4e 6a
      """)

  def bsk,
    do:
      from_hex("""
        5d ab 08 7e 62 4a 8a 4b
        79 e1 7f 8b 83 80 0e e6
        6f 3b b1 29 26 18 b6 fd
        1c 2f 8b 27 ff 88 e0 eb
      """)

  def bpk,
    do:
      from_hex("""
       de 9e db 7d 7b 7d c1 b4
       d3 5b 61 c2 ec e4 35 37
       3f 83 43 c8 5b 78 67 4d
       ad fc 7e 14 6f 88 2b 4f
      """)

  def n,
    do:
      from_hex("""
        69 69 6e e9 55 b6 2b 73
        cd 62 bd a8 75 fc 73 d6
        82 19 e0 03 6b 7a 0b 37
      """)

  def m,
    do:
      from_hex("""
         be 07 5f c5 3c 81 f2 d5
         cf 14 13 16 eb eb 0c 7b
         52 28 c5 2a 4c 62 cb d4
         4b 66 84 9b 64 24 4f fc
         e5 ec ba af 33 bd 75 1a
         1a c7 28 d4 5e 6c 61 29
         6c dc 3c 01 23 35 61 f4
         1d b6 6c ce 31 4a db 31
         0e 3b e8 25 0c 46 f0 6d
         ce ea 3a 7f a1 34 80 57
         e2 f6 55 6a d6 b1 31 8a
         02 4a 83 8f 21 af 1f de
         04 89 77 eb 48 f5 9f fd
         49 24 ca 1c 60 90 2e 52
         f0 a0 89 bc 76 89 70 40
         e0 82 f9 37 76 38 48 64
         5e 07 05
      """)

  def c,
    do:
      from_hex("""
      f3 ff c7 70 3f 94 00 e5
      2a 7d fb 4b 3d 33 05 d9
      8e 99 3b 9f 48 68 12 73
      c2 96 50 ba 32 fc 76 ce
      48 33 2e a7 16 4d 96 a4
      47 6f b8 c5 31 a1 18 6a
      c0 df c1 7c 98 dc e8 7b
      4d a7 f0 11 ec 48 c9 72
      71 d2 c2 0f 9b 92 8f e2
      27 0d 6f b8 63 d5 17 38
      b4 8e ee e3 14 a7 cc 8a
      b9 32 16 45 48 e5 26 ae
      90 22 43 68 51 7a cf ea
      bd 6b b3 73 2b c0 e9 da
      99 83 2b 61 ca 01 b6 de
      56 24 4a 9e 88 d5 f9 b3
      79 73 f6 22 a4 3d 14 a6
      59 9b 1f 65 4c b4 5a 74
      e3 55 a5
      """)

  def sec,
    do:
      from_hex("""
        1b 27 55 64 73 e9 85 d4
        62 cd 51 19 7a 9a 46 c7
        60 09 54 9e ac 64 74 f2
        06 c4 ee 08 44 f6 83 89
      """)
end
