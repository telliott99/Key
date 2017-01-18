import DataHelper

public class BinaryData :  Collection, 
    CustomStringConvertible {
    public var data = Array<UInt8>()
    public typealias Index = Int
    
    public init(_ data: [UInt8] = []) {
        self.data = data
    }
    public convenience init(_ input: String) {
        let bytes: [UInt8] = hexToBytes(input)
        self.init(bytes)
    }
    public var description: String {
        get { 
            return "0x" + byteArrayToHex(data) 
        }
    }
    public var startIndex: Index { 
        return 0 
    }
    public var endIndex: Index { 
        return data.count 
    }
    public func index(after i: Index) -> Index {
        return data.index(after: i)
    }
    public subscript(position: Index) -> UInt8 {
        get { 
            return data[position] 
        }
    }
    public subscript(bounds: Range<Int>) -> [UInt8] {
        get { 
            return Array(data[bounds]) 
        }
        set { 
            data[bounds] = ArraySlice(newValue) 
        }
    }
}

func testBinaryData() {
    let b = BinaryData(nRandomBytes(10))
    print(b)
    let s = "\(b)"
    print(s)
    let b2 = BinaryData(s)
    print(b2)
}

// testBinaryData()