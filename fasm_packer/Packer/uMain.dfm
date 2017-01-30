object FormMain: TFormMain
  Left = 192
  Top = 124
  Width = 306
  Height = 215
  Caption = 'FASM Packer'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object GroupBox1: TGroupBox
    Left = 8
    Top = 8
    Width = 273
    Height = 161
    Caption = 'Builder'
    TabOrder = 0
    object Label1: TLabel
      Left = 8
      Top = 28
      Width = 37
      Height = 13
      Caption = 'Loader:'
    end
    object Label2: TLabel
      Left = 8
      Top = 60
      Width = 20
      Height = 13
      Caption = 'File:'
    end
    object Label3: TLabel
      Left = 8
      Top = 92
      Width = 39
      Height = 13
      Caption = 'Section:'
    end
    object EdtLoader: TEdit
      Left = 56
      Top = 24
      Width = 169
      Height = 21
      TabOrder = 0
    end
    object BtnLoader: TButton
      Left = 232
      Top = 22
      Width = 33
      Height = 25
      Caption = '...'
      TabOrder = 1
      OnClick = BtnLoaderClick
    end
    object EdtFile: TEdit
      Left = 56
      Top = 56
      Width = 169
      Height = 21
      TabOrder = 2
    end
    object BtnFile: TButton
      Left = 232
      Top = 54
      Width = 33
      Height = 25
      Caption = '...'
      TabOrder = 3
      OnClick = BtnFileClick
    end
    object EdtSection: TEdit
      Left = 56
      Top = 88
      Width = 169
      Height = 21
      TabOrder = 4
      Text = '.Xash'
    end
    object BtnPack: TButton
      Left = 152
      Top = 120
      Width = 75
      Height = 25
      Caption = 'Pack'
      TabOrder = 5
      OnClick = BtnPackClick
    end
    object CheckEOF: TCheckBox
      Left = 56
      Top = 124
      Width = 49
      Height = 17
      Caption = 'EOF'
      TabOrder = 6
    end
  end
  object XPManifest1: TXPManifest
    Left = 200
  end
  object OpenExe: TOpenDialog
    Filter = '*.exe|*.exe'
    Left = 168
  end
  object SaveExe: TSaveDialog
    DefaultExt = 'exe'
    Left = 136
  end
end
