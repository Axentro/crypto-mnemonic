require "./spec_helper"

include Crypto::Mnemonic

describe Mnemonic do
  describe "#new" do
    it "should return some english words from mnemonic wordlist" do
      Util.mnemonic_word_list.first.should eq "like"
      Util.mnemonic_word_list[1125].should eq "hello"
      Util.mnemonic_word_list[30].should eq "world"
      Util.mnemonic_word_list.last.should eq "weary"
    end
    it "should raise an error if a non 32 bit argument is supplied" do
      expect_raises(Exception, "Can only generate 32/64/96/128/256 bit passwords") do
        Mnemonic.new(7)
      end
    end
    it "should accept a byte array as a seed" do
      Mnemonic.new(Mnemonic.new(32).seed).seed.size.should eq(1)
    end
    it "should have 96 as default" do
      Mnemonic.new.to_words.size.should eq(9)
    end
    it "should make seeds of the correct length" do
      Mnemonic.new(32).seed.size.should eq(1)
      Mnemonic.new(64).seed.size.should eq(2)
      Mnemonic.new(96).seed.size.should eq(3)
      Mnemonic.new(128).seed.size.should eq(4)
      Mnemonic.new(256).seed.size.should eq(8)
    end
  end

  describe "#to_words" do
    it "should generate a word list" do
      Mnemonic.new.to_words.size.should eq(9)
    end

    it "it should recover mnemonic from words" do
      Util.mnemonic_from_words(Mnemonic.new.to_words).seed.size.should eq(3)
    end
  end

  describe "#to_hex" do
    it "should generate a hex string" do
      Mnemonic.new.to_hex.size.should eq(24)
    end

    it "it should recover mnemonic from hex" do
      Util.mnemonic_from_hex(Mnemonic.new.to_hex).seed.size.should eq(3)
    end
  end

  describe "functional tests" do
    it "should return deterministic results" do
      words = ["knowledge",
               "consider",
               "pop",
               "path",
               "vision",
               "night",
               "melt",
               "soar",
               "caught"]
      hex = "eda5894997023e7093db0199"
      m = Util.mnemonic_from_words(words)
      m.to_hex.should eq(hex)

      m2 = Util.mnemonic_from_hex(hex)
      m2.to_words.should eq(words)
    end
  end
end
