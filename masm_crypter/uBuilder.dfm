object Form1: TForm1
  Left = 609
  Top = 132
  Width = 385
  Height = 239
  Caption = 'ASM Packer'
  Color = clWhite
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
    Width = 353
    Height = 97
    Caption = 'Files'
    TabOrder = 0
    object Label1: TLabel
      Left = 8
      Top = 24
      Width = 44
      Height = 13
      Caption = 'Crypter :'
    end
    object Label3: TLabel
      Left = 8
      Top = 48
      Width = 29
      Height = 13
      Caption = 'Stub :'
    end
    object EdtCrypter: TEdit
      Left = 80
      Top = 20
      Width = 217
      Height = 21
      TabOrder = 0
    end
    object BtnCrypter: TButton
      Left = 304
      Top = 20
      Width = 43
      Height = 21
      Caption = '...'
      TabOrder = 1
      OnClick = BtnCrypterClick
    end
    object BtnBinder: TButton
      Left = 304
      Top = 68
      Width = 43
      Height = 21
      Caption = '...'
      TabOrder = 2
      OnClick = BtnBinderClick
    end
    object EdtBinder: TEdit
      Left = 80
      Top = 68
      Width = 217
      Height = 21
      TabOrder = 3
    end
    object BtnStub: TButton
      Left = 304
      Top = 44
      Width = 43
      Height = 21
      Caption = '...'
      TabOrder = 4
      OnClick = BtnStubClick
    end
    object EdtStub: TEdit
      Left = 80
      Top = 44
      Width = 217
      Height = 21
      TabOrder = 5
    end
    object ChkBinder: TCheckBox
      Left = 8
      Top = 72
      Width = 65
      Height = 17
      Caption = 'Binder :'
      TabOrder = 6
    end
  end
  object GroupBox2: TGroupBox
    Left = 8
    Top = 112
    Width = 353
    Height = 81
    Caption = 'Build'
    TabOrder = 1
    object BtnIcon: TButton
      Left = 304
      Top = 20
      Width = 43
      Height = 21
      Caption = '...'
      TabOrder = 0
      OnClick = BtnIconClick
    end
    object EdtIcon: TEdit
      Left = 80
      Top = 20
      Width = 217
      Height = 21
      TabOrder = 1
    end
    object BtnBuild: TButton
      Left = 112
      Top = 48
      Width = 75
      Height = 25
      Caption = 'Build'
      TabOrder = 2
      OnClick = BtnBuildClick
    end
    object BtnAbout: TButton
      Left = 208
      Top = 48
      Width = 75
      Height = 25
      Caption = 'About'
      TabOrder = 3
    end
    object ChkIcon: TCheckBox
      Left = 8
      Top = 24
      Width = 57
      Height = 17
      Caption = 'Icon :'
      TabOrder = 4
    end
  end
  object XPManifest1: TXPManifest
    Left = 152
    Top = 8
  end
  object OpenExe: TOpenDialog
    Filter = '*.exe|*.exe'
    Left = 184
    Top = 8
  end
  object SaveExe: TSaveDialog
    DefaultExt = '.exe'
    Filter = '*.exe|*.exe'
    Left = 248
    Top = 8
  end
  object OpenIcon: TOpenDialog
    Filter = '*.ico|*.ico'
    Left = 216
    Top = 8
  end
end
