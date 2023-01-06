# Palkeoramix decompiler. 

def storage:
  owner is addr at storage 0
  stor1 is mapping of uint8 at storage 1

def admin(address _param1): # not payable
  require calldata.size - 4 >=ΓÇ▓ 32
  require _param1 == _param1
  return bool(stor1[_param1])

def owner(): # not payable
  return owner

#
#  Regular functions
#

def _fallback() payable: # default function
  revert

def renounceOwnership(): # not payable
  if owner != caller:
      revert with 0, 'Ownable: caller is not the owner'
  owner = 0
  log OwnershipTransferred(
        address previousOwner=owner,
        address newOwner=0)

def unknowne0a1fcf6(uint256 _param1): # not payable
  require calldata.size - 4 >=ΓÇ▓ 32
  require _param1 == addr(_param1)
  return (Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)

def unknowna04e9b18(uint256 _param1): # not payable
  require calldata.size - 4 >=ΓÇ▓ 32
  require _param1 == _param1
  if not stor1[caller]:
      revert with 0, 'not admin'
  call caller with:
     value _param1 wei
       gas gas_remaining wei
  if not ext_call.success:
      revert with 0, 'TransferHelper: ETH_TRANSFER_FAILED'

def setAdmin(address _admin, bool _isAdmin): # not payable
  require calldata.size - 4 >=ΓÇ▓ 64
  require _admin == _admin
  require _isAdmin == _isAdmin
  if owner != caller:
      revert with 0, 'Ownable: caller is not the owner'
  stor1[addr(_admin)] = uint8(_isAdmin)

def transferOwnership(address _newOwner): # not payable
  require calldata.size - 4 >=ΓÇ▓ 32
  require _newOwner == _newOwner
  if owner != caller:
      revert with 0, 'Ownable: caller is not the owner'
  if not _newOwner:
      revert with 0x8c379a000000000000000000000000000000000000000000000000000000000, 'Ownable: new owner is the zero address'
  owner = _newOwner
  log OwnershipTransferred(
        address previousOwner=owner,
        address newOwner=_newOwner)

def unknownf83a97c5(uint256 _param1, uint256 _param2): # not payable
  require calldata.size - 4 >=ΓÇ▓ 64
  require _param1 == addr(_param1)
  require _param2 == _param2
  if not stor1[caller]:
      revert with 0, 'not admin'
  require ext_code.size(addr(_param1))
  call addr(_param1).transfer(address to, uint256 tokens) with:
       gas gas_remaining wei
      args caller, _param2
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == bool(ext_call.return_data[0])

def unknown51d0a287(uint256 _param1, uint256 _param2, uint256 _param3): # not payable
  require calldata.size - 4 >=ΓÇ▓ 96
  require _param1 == addr(_param1)
  require _param2 == addr(_param2)
  require _param3 == _param3
  if not stor1[caller]:
      revert with 0, 'not admin'
  require ext_code.size(addr(_param2))
  static call addr(_param2).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args this.address
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  require ext_code.size(addr(_param1))
  static call addr(_param1).0xdfe1681 with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  require ext_code.size(addr(_param1))
  if addr(_param2) == ext_call.return_data[12 len 20]:
      static call addr(_param1).token1() with:
              gas gas_remaining wei
  else:
      static call addr(_param1).0xdfe1681 with:
              gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  if ext_call.return_data < 10^17:
      revert with 'NH{q', 17
  if ext_call.return_data <= 0:
      revert with 0, 'r'
  require ext_code.size(addr(_param2))
  call addr(_param2).transfer(address to, uint256 tokens) with:
       gas gas_remaining wei
      args addr(_param1), ext_call.return_data[0] - 10^17
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == bool(ext_call.return_data[0])
  require ext_code.size(addr(_param1))
  static call addr(_param1).getReserves() with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 96
  require ext_call.return_data == ext_call.return_data[18 len 14]
  require ext_call.return_data == ext_call.return_data[50 len 14]
  require ext_call.return_data == ext_call.return_data[92 len 4]
  require ext_code.size(addr(_param1))
  static call addr(_param1).0xdfe1681 with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  require ext_code.size(addr(_param2))
  static call addr(_param2).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args addr(_param1)
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  if addr(_param2) == ext_call.return_data[12 len 20]:
      if ext_call.return_data < Mask(112, 0, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if Mask(144, 112, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(144, 112, ext_call.return_data and _param3 > -1 / Mask(144, 112, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3) and Mask(112, 0, ext_call.return_data > -1 / (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * ext_call.return_data * _param3) + (Mask(112, 0, ext_call.return_data * _param3) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 18
  else:
      if ext_call.return_data < Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if ext_call.return_data and _param3 > -1 / ext_call.return_data[0] - Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3) and Mask(112, 0, ext_call.return_data > -1 / (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * ext_call.return_data * _param3) + (Mask(112, 0, ext_call.return_data * _param3) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 18
  require ext_code.size(addr(_param1))
  static call addr(_param1).0xdfe1681 with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  ...  # Decompilation aborted, sorry: ("decompilation didn't finish",)

def unknown8488b2ba(uint256 _param1, uint256 _param2, uint256 _param3, uint256 _param4, uint256 _param5, uint256 _param6): # not payable
  require calldata.size - 4 >=ΓÇ▓ 192
  require _param1 == addr(_param1)
  require _param2 == addr(_param2)
  require _param3 == _param3
  require _param4 == _param4
  require _param5 == Mask(112, 0, _param5)
  require _param6 == _param6
  if not stor1[caller]:
      revert with 0, 'not admin'
  require ext_code.size(Mask(64, 96, _param2 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
  static call Mask(64, 96, _param2 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args (Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  if Mask(112, 0, _param5) < ext_call.return_data[0]:
      revert with 0, 'x'
  if _param6 != block.number:
      revert with 0, 'xxx'
  require ext_code.size(Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
  static call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.getReserves() with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 96
  require ext_call.return_data == ext_call.return_data[18 len 14]
  require ext_call.return_data == ext_call.return_data[50 len 14]
  require ext_call.return_data == ext_call.return_data[92 len 4]
  require ext_code.size(Mask(64, 96, _param2 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
  call Mask(64, 96, _param2 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.transfer(address to, uint256 tokens) with:
       gas gas_remaining wei
      args Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) << 96, _param3
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == bool(ext_call.return_data[0])
  require ext_code.size(Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
  static call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.0xdfe1681 with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  if _param3 <= 0:
      revert with 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT'
  if Mask(64, 96, _param2 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96 == ext_call.return_data[12 len 20]:
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if _param3 and _param4 > -1 / _param3:
          revert with 'NH{q', 17
      if _param3 * _param4 and Mask(112, 0, ext_call.return_data > -1 / _param3 * _param4:
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * _param3 * _param4) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data_param3 * _param4):
          revert with 'NH{q', 18
      require ext_code.size(Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
      static call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.0xdfe1681 with:
              gas gas_remaining wei
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      require return_data.size >=ΓÇ▓ 32
      require ext_call.return_data == ext_call.return_data[12 len 20]
      require ext_code.size(Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
      if Mask(64, 96, _param2 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96 == ext_call.return_data[12 len 20]:
          call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.0x22c0d9f with:
               gas gas_remaining wei
              args 0, _param3 * _param4 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data_param3 * _param4), addr(this.address), 128, 0
      else:
          call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.0x22c0d9f with:
               gas gas_remaining wei
              args _param3 * _param4 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data_param3 * _param4), 0, addr(this.address), 128, 0
  else:
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if _param3 and _param4 > -1 / _param3:
          revert with 'NH{q', 17
      if _param3 * _param4 and Mask(112, 0, ext_call.return_data > -1 / _param3 * _param4:
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * _param3 * _param4) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data_param3 * _param4):
          revert with 'NH{q', 18
      require ext_code.size(Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
      static call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.0xdfe1681 with:
              gas gas_remaining wei
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      require return_data.size >=ΓÇ▓ 32
      require ext_call.return_data == ext_call.return_data[12 len 20]
      require ext_code.size(Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96)
      if Mask(64, 96, _param2 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96 == ext_call.return_data[12 len 20]:
          call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.0x22c0d9f with:
               gas gas_remaining wei
              args 0, _param3 * _param4 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data_param3 * _param4), addr(this.address), 128, 0
      else:
          call Mask(64, 96, _param1 << 96 xor 0x52f656151e1ee5d39006d4090dd446f5422d5c7f000000000000000000000000) >> 96.0x22c0d9f with:
               gas gas_remaining wei
              args _param3 * _param4 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data_param3 * _param4), 0, addr(this.address), 128, 0
  if block.gasprice < 14 * 10^9:
  else:
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      if calldata.size > 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:
          revert with 'NH{q', 17
      if 21000 > -gas_remaining - 1:
          revert with 'NH{q', 17
      if gas_remaining + 21000 < gas_remaining:
          revert with 'NH{q', 17
      if 21000 > -(16 * calldata.size) - 1:
          revert with 'NH{q', 17
      if (16 * calldata.size) + 21000 > -14155:
          revert with 'NH{q', 17
      require ext_code.size(0x4946c0e9f43f4dee607b0ef1fa1c)
      call 0x0000000000004946c0e9f43f4dee607b0ef1fa1c.freeUpTo(uint256 value) with:
           gas gas_remaining wei
          args ((16 * calldata.size) + 35154 / 41947)
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]

def unknown34e8deda(uint256 _param1, uint256 _param2, uint256 _param3): # not payable
  require calldata.size - 4 >=ΓÇ▓ 96
  require _param1 == addr(_param1)
  require _param2 == addr(_param2)
  require _param3 == _param3
  if not stor1[caller]:
      revert with 0, 'not admin'
  require ext_code.size(addr(_param2))
  static call addr(_param2).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args this.address
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  if ext_call.return_data <= 0:
      revert with 0, 'r'
  require ext_code.size(addr(_param2))
  call addr(_param2).transfer(address to, uint256 tokens) with:
       gas gas_remaining wei
      args addr(_param1), ext_call.return_data[0]
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == bool(ext_call.return_data[0])
  require ext_code.size(addr(_param1))
  static call addr(_param1).getReserves() with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 96
  require ext_call.return_data == ext_call.return_data[18 len 14]
  require ext_call.return_data == ext_call.return_data[50 len 14]
  require ext_call.return_data == ext_call.return_data[92 len 4]
  require ext_code.size(addr(_param1))
  static call addr(_param1).0xdfe1681 with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  require ext_code.size(addr(_param2))
  static call addr(_param2).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args addr(_param1)
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  if addr(_param2) == ext_call.return_data[12 len 20]:
      if ext_call.return_data < Mask(112, 0, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if Mask(144, 112, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(144, 112, ext_call.return_data and _param3 > -1 / Mask(144, 112, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3) and Mask(112, 0, ext_call.return_data > -1 / (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * ext_call.return_data * _param3) + (Mask(112, 0, ext_call.return_data * _param3) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 18
      require ext_code.size(addr(_param1))
      static call addr(_param1).0xdfe1681 with:
              gas gas_remaining wei
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      require return_data.size >=ΓÇ▓ 32
      require ext_call.return_data == ext_call.return_data[12 len 20]
      require ext_code.size(addr(_param1))
      if addr(_param2) == ext_call.return_data[12 len 20]:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args 0, (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), addr(this.address), 128, 0
      else:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), 0, addr(this.address), 128, 0
  else:
      if ext_call.return_data < Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if ext_call.return_data and _param3 > -1 / ext_call.return_data[0] - Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3) and Mask(112, 0, ext_call.return_data > -1 / (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * ext_call.return_data * _param3) + (Mask(112, 0, ext_call.return_data * _param3) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 18
      require ext_code.size(addr(_param1))
      static call addr(_param1).0xdfe1681 with:
              gas gas_remaining wei
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      require return_data.size >=ΓÇ▓ 32
      require ext_call.return_data == ext_call.return_data[12 len 20]
      require ext_code.size(addr(_param1))
      if addr(_param2) == ext_call.return_data[12 len 20]:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args 0, (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), addr(this.address), 128, 0
      else:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), 0, addr(this.address), 128, 0
  if block.gasprice < 14 * 10^9:
  else:
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      if calldata.size > 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:
          revert with 'NH{q', 17
      if 21000 > -gas_remaining - 1:
          revert with 'NH{q', 17
      if gas_remaining + 21000 < gas_remaining:
          revert with 'NH{q', 17
      if 21000 > -(16 * calldata.size) - 1:
          revert with 'NH{q', 17
      if (16 * calldata.size) + 21000 > -14155:
          revert with 'NH{q', 17
      require ext_code.size(0x4946c0e9f43f4dee607b0ef1fa1c)
      call 0x0000000000004946c0e9f43f4dee607b0ef1fa1c.freeUpTo(uint256 value) with:
           gas gas_remaining wei
          args ((16 * calldata.size) + 35154 / 41947)
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]

def unknown58cc30c0(uint256 _param1, uint256 _param2, uint256 _param3, uint256 _param4): # not payable
  require calldata.size - 4 >=ΓÇ▓ 128
  require _param1 == addr(_param1)
  require _param2 == addr(_param2)
  require _param3 == _param3
  require _param4 == _param4
  if not stor1[caller]:
      revert with 0, 'not admin'
  require ext_code.size(addr(_param2))
  static call addr(_param2).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args this.address
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  if ext_call.return_data <= 0:
      revert with 0, 's'
  require ext_code.size(addr(_param2))
  call addr(_param2).transfer(address to, uint256 tokens) with:
       gas gas_remaining wei
      args addr(_param1), ext_call.return_data[0]
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == bool(ext_call.return_data[0])
  require ext_code.size(addr(_param1))
  static call addr(_param1).0xdfe1681 with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  require ext_code.size(addr(_param1))
  if addr(_param2) == ext_call.return_data[12 len 20]:
      static call addr(_param1).token1() with:
              gas gas_remaining wei
  else:
      static call addr(_param1).0xdfe1681 with:
              gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  require ext_code.size(addr(ext_call.return_data))
  static call addr(ext_call.return_data).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args this.address
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  require ext_code.size(addr(_param1))
  static call addr(_param1).getReserves() with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 96
  require ext_call.return_data == ext_call.return_data[18 len 14]
  require ext_call.return_data == ext_call.return_data[50 len 14]
  require ext_call.return_data == ext_call.return_data[92 len 4]
  require ext_code.size(addr(_param1))
  static call addr(_param1).0xdfe1681 with:
          gas gas_remaining wei
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[12 len 20]
  require ext_code.size(addr(_param2))
  static call addr(_param2).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args addr(_param1)
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  if addr(_param2) == ext_call.return_data[12 len 20]:
      if ext_call.return_data < Mask(112, 0, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if Mask(144, 112, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(144, 112, ext_call.return_data and _param3 > -1 / Mask(144, 112, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3) and Mask(112, 0, ext_call.return_data > -1 / (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[0]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * ext_call.return_data * _param3) + (Mask(112, 0, ext_call.return_data * _param3) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 18
      require ext_code.size(addr(_param1))
      static call addr(_param1).0xdfe1681 with:
              gas gas_remaining wei
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      require return_data.size >=ΓÇ▓ 32
      require ext_call.return_data == ext_call.return_data[12 len 20]
      require ext_code.size(addr(_param1))
      if addr(_param2) == ext_call.return_data[12 len 20]:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args 0, (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), addr(this.address), 128, 0
      else:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), 0, addr(this.address), 128, 0
  else:
      if ext_call.return_data < Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_INPUT_AMOUNT'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if Mask(112, 0, ext_call.return_data <= 0:
          revert with 0, 'PancakeLibrary: INSUFFICIENT_LIQUIDITY'
      if ext_call.return_data and _param3 > -1 / ext_call.return_data[0] - Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3) and Mask(112, 0, ext_call.return_data > -1 / (ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 17
      if Mask(112, 0, ext_call.return_data and 10^6 > -1 / Mask(112, 0, ext_call.return_data[32]):
          revert with 'NH{q', 17
      if 10^6 * Mask(112, 0, ext_call.return_data > (-1 * ext_call.return_data * _param3) + (Mask(112, 0, ext_call.return_data * _param3) - 1:
          revert with 'NH{q', 17
      if not (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3):
          revert with 'NH{q', 18
      require ext_code.size(addr(_param1))
      static call addr(_param1).0xdfe1681 with:
              gas gas_remaining wei
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      require return_data.size >=ΓÇ▓ 32
      require ext_call.return_data == ext_call.return_data[12 len 20]
      require ext_code.size(addr(_param1))
      if addr(_param2) == ext_call.return_data[12 len 20]:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args 0, (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), addr(this.address), 128, 0
      else:
          call addr(_param1).0x22c0d9f with:
               gas gas_remaining wei
              args (ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data * _param3 * Mask(112, 0, ext_call.return_data / (10^6 * Mask(112, 0, ext_call.return_data * _param3) - (Mask(112, 0, ext_call.return_data * _param3), 0, addr(this.address), 128, 0
  if block.gasprice < 14 * 10^9:
  else:
      if not ext_call.success:
          revert with ext_call.return_data[0 len return_data.size]
      if calldata.size > 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:
          revert with 'NH{q', 17
      if 21000 > -gas_remaining - 1:
          revert with 'NH{q', 17
      if gas_remaining + 21000 < gas_remaining:
          revert with 'NH{q', 17
      if 21000 > -(16 * calldata.size) - 1:
          revert with 'NH{q', 17
      if (16 * calldata.size) + 21000 > -14155:
          revert with 'NH{q', 17
      require ext_code.size(0x4946c0e9f43f4dee607b0ef1fa1c)
      call 0x0000000000004946c0e9f43f4dee607b0ef1fa1c.freeUpTo(uint256 value) with:
           gas gas_remaining wei
          args ((16 * calldata.size) + 35154 / 41947)
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require ext_code.size(addr(ext_call.return_data))
  static call addr(ext_call.return_data).balanceOf(address tokenOwner) with:
          gas gas_remaining wei
         args this.address
  if not ext_call.success:
      revert with ext_call.return_data[0 len return_data.size]
  require return_data.size >=ΓÇ▓ 32
  require ext_call.return_data == ext_call.return_data[0]
  if ext_call.return_data < ext_call.return_data[0]:
      revert with 'NH{q', 17
  if 0 < _param4:
      revert with 0, 't'


