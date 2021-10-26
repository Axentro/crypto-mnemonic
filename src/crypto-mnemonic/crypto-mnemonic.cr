require "random"

module Crypto::Mnemonic
  class Mnemonic
    getter seed : Array(UInt32)

    def initialize(bits : Int32 = 96)
      raise "Can only generate 32/64/96/128/256 bit passwords" if (bits % 32 != 0)
      @seed = get_random(bits)
    end

    def initialize(seed : Array(UInt32))
      @seed = seed
    end

    private def get_random(bits) : Array(UInt32)
      r = (1..(bits / 32)).map do
        rand(bits)
      end
      hex = r.reduce("") do |res, s|
        b = s.to_s(16)
        b = "0#{b}" if b.size === 1
        res + b
      end
      if hex.hexbytes? == nil
        return get_random(bits)
      end
      length = (bits / 8) * 2
      if hex.size != length
       return get_random(bits)
      end
      return r
    end

    def to_words : Array(String)
      n = Util.mnemonic_word_list.size
      phrase = @seed.reduce([] of String) do |words, seed|
        x = seed
        w1 = x % n
        w2 = (((x / n).to_i >> 0) + w1) % n
        w3 = (((((x / n).to_i >> 0) / n).to_i >> 0) + w2) % n
        words.push(Util.mnemonic_word_list[w1])
        words.push(Util.mnemonic_word_list[w2])
        words.push(Util.mnemonic_word_list[w3])
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
