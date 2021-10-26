require "./spec_helper"

include Crypto::Mnemonic

describe Bip0039 do
  describe "#new" do
    it "should return some english words from bip-0039 wordlist" do
      Util.bip0039_word_list.first.should eq "abandon"
      Util.bip0039_word_list[854].should eq "hello"
      Util.bip0039_word_list[2029].should eq "world"
      Util.bip0039_word_list.last.should eq "zoo"
    end
    it "should raise an error if a non 32 bit argument is supplied" do
      expect_raises(Exception, "Can only generate 128/160/192/224/256 bit seeds") do
        Bip0039.new(7)
      end
    end
    it "should accept a byte array as a seed" do
      Bip0039.new(Bip0039.new(128).seed).seed.size.should eq(4)
    end
    it "should have 128 as default" do
      Bip0039.new.to_words.size.should eq(12)
    end
    it "should make seeds of the correct length" do
      Bip0039.new(128).seed.size.should eq(4)
      Bip0039.new(160).seed.size.should eq(5)
      Bip0039.new(192).seed.size.should eq(6)
      Bip0039.new(224).seed.size.should eq(7)
      Bip0039.new(256).seed.size.should eq(8)
    end
  end

  describe "#to_words" do
    it "should generate a word list" do
      Bip0039.new.to_words.size.should eq(12)
    end

    it "it should recover bip0039 from words" do
      Util.bip0039_from_words(Bip0039.new.to_words).seed.size.should eq(4)
    end
  end

  describe "#to_hex" do
    it "should generate a hex string" do
      Bip0039.new.to_hex.size.should eq(32)
    end

    it "should recover bip0039 from hex" do
      Util.bip0039_from_hex(Bip0039.new.to_hex).seed.size.should eq(4)
    end
  end

  describe "functional tests" do
    it "should return deterministic results" do
      words = ["onion",
               "ecology",
               "match",
               "hammer",
               "round",
               "category",
               "spend",
               "snow",
               "brick",
               "good",
               "jazz",
               "private"]
      hex = "85aad4d6cf94fb449c7f168a6784c323"
      m = Util.bip0039_from_words(words)
      m.to_hex.should eq(hex)

      m2 = Util.bip0039_from_hex(hex)
      m2.to_words.should eq(words)
    end
  end
end
