require "random"

module Crypto::Mnemonic
  class Bip0039
    getter seed : Array(UInt32)

    def initialize
      @seed = getRandom(128)
    end

    def initialize(bits : Int32 = 128)
      if bits % 32 != 0 || bits < 128 || bits > 256
        raise "Can only generate 128/160/192/224/256 bit seeds"
      end
      @seed = getRandom(bits)
    end

    def initialize(seed : Array(UInt32))
      @seed = seed
    end

    private def getRandom(bits) : Array(UInt32)
      r = (1..(bits / 32)).map do
        rand(bits)
      end
      hex = r.reduce("") do |res, s|
        b = s.to_s(16)
        b = "0#{b}" if b.size === 1
        res + b
      end
      if hex.hexbytes? == nil
        return getRandom(bits)
      end
      length = (bits / 8) * 2
      if hex.size != length
       return getRandom(bits)
      end
      return r
    end

    def to_words : Array(String)
      n = Util.bip0039_word_list.size
      phrase = @seed.reduce([] of String) do |words, seed|
        x = seed
        w1 = x % n
        w2 = (((x / n).to_i >> 0) + w1) % n
        w3 = (((((x / n).to_i >> 0) / n).to_i >> 0) + w2) % n
        words.push(Util.bip0039_word_list[w1])
        words.push(Util.bip0039_word_list[w2])
        words.push(Util.bip0039_word_list[w3])
      end
      return phrase
    end

    def to_hex : String
      hex = @seed.reduce("") do |res, s|
        b = s.to_s(16)
        b = "0#{b}" if b.size === 1
        res + b
      end
      return hex
    end

    private def next_u
      Crystal::System::Random.next_u
    end

    private def random_bytes(buf : Bytes)
      Crystal::System::Random.random_bytes(buf)
    end

    private def rand(needed_parts = nil) : UInt32
      needed_bytes =
        if needed_parts
          needed_parts * sizeof(typeof(next_u))
        else
          sizeof(UInt32)
        end

      buf = uninitialized UInt8[sizeof(UInt32)]

      if needed_bytes < sizeof(UInt32)
        bytes = Slice.new(buf.to_unsafe, needed_bytes)
        random_bytes(bytes)

        bytes.reduce(UInt32.new(0)) do |result, byte|
          (result << 8) | byte
        end
      else
        random_bytes(buf.to_slice)
        buf.unsafe_as(UInt32)
      end
    end
  end
end
