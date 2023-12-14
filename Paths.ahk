/**
 * An object-oriented file system class that provides various methods and properties for working with files and directories.
 * @class
 */
Class Path {
	/**
	 * Initializes a new instance of Path object.
	 * Each component may be a string or a Path object to be used in constructing the new Path object.
	 * @param {...Path|...String} Components - The path or path components to construct the path.
	 */
	__New(Components*) {
		if !Components.Length {
			this.Path := A_WorkingDir
			return
		}
		for Component in Components {
			if Type(Component) = "Path" {
				Component := Component.Path
			}
			Path .= Component "\"
		}
		Path := RegExReplace(Path, "\\{2,}|\/", "\")
		this.Path := RTrim(Path, "\")
	}

	/**
	 * Sets the current working directory to the specified path (must be a valid directory path).
	 * @param {Path|String} [WorkingDir=A_WorkingDir] - The path to set as the current working directory. The path may be a string or a Path object.
	 * @returns {Path} - The updated current working directory Path object.
	 * @throws {OSError} - If the path does not exist.
	 * @throws {Error} - If the path points to a file.
	 */
	static CWD(WorkingDir := A_WorkingDir) {
		if Type(WorkingDir) != "Path" {
			WorkingDir := Path(WorkingDir)
		}
		if !WorkingDir.Exists {
			throw OSError(3, -1, '"' WorkingDir.Path '"')
		}
		if !WorkingDir.IsDir {
			throw Error("Path points to a file.", -1, '"' WorkingDir.Path '"')
		}
		SetWorkingDir(WorkingDir.Path)
		return WorkingDir
	}

	/**
	 * Copies the file or directory represented by the Path object to the specified target location.
	 * @param {Path|String} Target - The path to copy the file or directory to. The path may be a string or a Path object.
	 * @param {Boolean} [Overwrite=false] - If 1 or `true`, overwrite existing files or directories at the target location.
	 * @returns {Path} - The Path object of the copied file or directory.
	 */
	Copy(Target, Overwrite := false) {
		CurrentWorkingDir := A_WorkingDir
		Overwrite := !!Overwrite
		if Type(Target) = "Path" {
			Target := Target.Path
		}
		SetWorkingDir(this.Parent)
		if this.IsFile {
			FileCopy(this.Path, Target, Overwrite)
		}
		else if this.IsDir {
			DirCopy(this.Path, Target, Overwrite)
		}
		SetWorkingDir(CurrentWorkingDir)
		return Path(Target)
	}

	/**
	 * Retrieves details or properties of the file or folder.
	 * @param {String} Property - The property to retrieve details for.
	 * @returns {String} - The value of the specified property for the file or folder.
	 * @throws {OSError} - If the file or folder does not exist.
	 */
	Details(Property) {
		if !this.Exists {
			throw OSError(3, -1, '"' this.Path '"')
		}
		static Properties := Map()
		static ShellObj := ComObject("Shell.Application")
		if !Properties.Count {
			Properties.CaseSense := false
			FolderObj := ShellObj.NameSpace(A_WorkingDir)
			loop 321 {
				FileProperty := FolderObj.GetDetailsOf("", A_Index - 1)
				if FileProperty {
					Properties.Set(FileProperty, A_Index - 1)
				}
			}
		}
		if !Properties.Has(Property) {
			return
		}
		FolderObj := ShellObj.NameSpace(this.Parent)
		FileObj	:= FolderObj.ParseName(this.Name)
		FileProperty := FolderObj.GetDetailsOf(FileObj, Properties.Get(Property))
		return FileProperty
	}

	/**
	 * Calculates the checksum or hash value of the file using the specified algorithm.
	 * @param {String} Algorithm - The checksum or hash algorithm to use.
	 * * *Supported values are CRC32, MD2, MD4, MD5, SHA1, SHA256, SHA384, and SHA512.*
	 * @returns {String} - The checksum or hash value of the file.
	 * @throws {OSError} - If the file does not exist.
	 * @throws {Error} - If the path points to a directory.
	 * @throws {ValueError} - If the specified algorithm is invalid.
	 */
	Hash(Algorithm) {
		if !this.Exists {
			throw OSError(2, -1, '"' this.Path '"')
		}
		if !this.IsFile {
			throw Error("Path points to a directory.", -1, '"' this.Path '"')
		}
		static Algorithms := Map()
		if !Algorithms.Count {
			Algorithms.CaseSense := false
			Algorithms.Set(
				"CRC32", "", ; Value is not used
				"MD2", 0x00008001, ; CALG_MD2
				"MD4", 0x00008002, ; CALG_MD4
				"MD5", 0x00008003, ; CALG_MD5
				"SHA1", 0x00008004, ; CALG_SHA1
				"SHA256", 0x0000800C, ; CALG_SHA_256
				"SHA384", 0x0000800D, ; CALG_SHA_384
				"SHA512", 0x0000800E ; CALG_SHA_512
			)
		}
		if !Algorithms.Has(Algorithm) {
			throw ValueError("Parameter #1 of " A_ThisFunc " is invalid.", -1, '"' Algorithm '"')
		}
		Data := Buffer(1024 ** 2)
		FileObj := this.Open("R")
		if Algorithm = "CRC32" {
			while !FileObj.AtEOF {
				BytesRead := FileObj.RawRead(Data)
				Checksum := DllCall("ntdll.dll\RtlComputeCrc32",
					"UInt", Checksum := Checksum ?? 0,
					"Ptr", Data,
					"UInt", BytesRead,
					"UInt"
				)
			}
			FileObj.Close()
			return Format("{:08x}", Checksum ?? 0)
		}
		DllCall("advapi32.dll\CryptAcquireContext",
			"Ptr*", &Key := 0, ; phProv
			"Ptr", 0, ; szContainer
			"Ptr", 0, ; szProvider
			"UInt", 0x00000018, ; dwProvType -> PROV_RSA_AES = 0x00000018
			"UInt", 0xF0000000 ; dwFlags -> CRYPT_VERIFYCONTEXT = 0xF0000000
		)
		DllCall("advapi32.dll\CryptCreateHash",
			"Ptr", Key, ; hProv
			"UInt", Algorithms[Algorithm], ; Algid
			"UInt", 0, ; hKey
			"UInt", 0, ; dwFlags
			"Ptr*", &HashObj := 0 ; *phHash
		)
		while !FileObj.AtEOF {
			BytesRead := FileObj.RawRead(Data)
			DllCall("advapi32.dll\CryptHashData",
				"Ptr", HashObj, ; hHash
				"Ptr", Data, ; *pbData
				"UInt", BytesRead, ; dwDataLen
				"UInt", 0 ; dwFlags
			)
		}
		FileObj.Close()
		DllCall("advapi32.dll\CryptGetHashParam",
			"Ptr", HashObj, ; hHash
			"UInt", 2, ; dwParam -> HP_HASHVAL = 2
			"Ptr", 0, ; *pbData
			"UInt*", &Data := 0, ; *pdwDataLen
			"UInt", 0 ; dwFlags
		)
		Data := Buffer(Data)
		DllCall("advapi32.dll\CryptGetHashParam",
			"Ptr", HashObj, ; hHash
			"UInt", 2, ; dwParam -> HP_HASHVAL = 2
			"Ptr", Data,  ; hHash
			"UInt*", Data.Size, ; *pdwDataLen
			"UInt", 0 ; dwFlags
		)
		DllCall("advapi32.dll\CryptDestroyHash", "Ptr", HashObj)
		DllCall("advapi32.dll\CryptReleaseContext", "Ptr", Key)
		Hash := Buffer(Data.Size * 4 + 1)
		DllCall("crypt32.dll\CryptBinaryToString",
			"Ptr", Data, ; *pbBinary
			"UInt", Data.Size, ; cbBinary
			"UInt", 0x4000000c, ; dwFlags -> CRYPT_STRING_NOCRLF = 0x40000000 | CRYPT_STRING_HEXRAW = 0x0000000c
			"Ptr", Hash, ; pszString
			"UInt*", Hash.Size ; *pcchString
		)
		return StrGet(Hash)
	}

	/**
	 * Iterates through the contents of the directory represented by the Path object.
	 * @param {Boolean} [Recursive=true] - If 1 or `true`, iterates through subdirectories recursively.
	 * @returns {Path[]} - An array of Path objects representing the children of the directory.
	 * @throws {OSError} - If the directory does not exist.
	 * @throws {Error} - If the path points to a file.
	 */
	IterDir(Recursive := true) {
		if !this.Exists {
			throw OSError(3, -1, '"' this.Path '"')
		}
		if !this.IsDir {
			throw Error("Path points to a file.", -1, '"' this.Path '"')
		}
		Recursive := !!Recursive
		Children := Array()
		loop files, this.Path "\*", Recursive ? "DFR" : "DF" {
			Children.Push(Path(A_LoopFileFullPath))
		}
		return Children
	}

	/**
	 * Filters the contents of the directory represented by the Path object based on a shell-style pattern.
	 * @param {String} [Pattern="*"] - The shell-style pattern to match against file or folder names.
	 * @param {Boolean} [Recursive=true] - If 1 or `true`, filters through subdirectories recursively.
	 * @param {Boolean} [CaseSense=false] - 0 or `false` if a match should be case-insensitive.
	 * @returns {Path[]} - An array of Path objects representing the children of the directory that match the shell-style pattern.
	 * @throws {OSError} - If the directory does not exist.
	 * @throws {Error} - If the path points to a file.
	 */
	Filter(Pattern := "*", CaseSense := false, Recursive := true) {
		if !this.Exists {
			throw OSError(3, -1, '"' this.Path '"')
		}
		if !this.IsDir {
			throw Error("Path points to a file.", -1, '"' this.Path '"')
		}
		CaseSense := !!CaseSense
		Pattern := Path.Translate(Pattern)
		Recursive := !!Recursive
		Result := Array()
		loop files, this.Path "\*", Recursive ? "DFR" : "DF" {
			if RegExMatch(A_LoopFileName, CaseSense ? "S)" Pattern : "iS)" Pattern) {
				Result.Push(Path(A_LoopFileFullPath))
			}
		}
		return Result
	}

	/**
	 * Joins path components to the current Path object.
	 * @param {...Path|...String} Components - The path components to join.
	 * Each component may be a string or a Path object to be used in constructing the new Path object.
	 * @returns {Path} - A new Path object formed by concatenating the current Path object with the provided components.
	 */
	Join(Components*) {
		Joined := this.Path "\"
		for Component in Components {
			if Type(Component) = "Path" {
				Component := Component.Path
			}
			Joined .= Component "\"
		}
		Joined := RegExReplace(Joined, "\\{2,}|\/", "\")
		Joined := RTrim(Joined, "\")
		return Path(Joined)
	}

	/**
	 * Checks if the file or directory name matches the specified shell-style pattern.
	 * @param {String} [Pattern="*"] - The shell-style pattern to match against the name.
	 * @param {Boolean} [CaseSense=false] - 0 or `false` if the match should be case-insensitive.
	 * @returns {Boolean} - 1 or `true` if the name matches the pattern.
	 */
	Match(Pattern := "*", CaseSense := false) {
		CaseSense := !!CaseSense
		Pattern := Path.Translate(Pattern)
		return RegExMatch(this.Name, CaseSense ? "S)" Pattern : "iS)" Pattern) ? true : false
	}

	/**
	 * Creates the directory specified by the Path object.
	 * @param {Boolean} [Parents=true] - If 1 or `true`, creates the specified directory including all necessary parent directories;
	 * otherwise 0 or `false`, only creates the specified directory.
	 * @throws {OSError} - If any of the Path object's parent directories do not exist.
	 */
	MkDir(Parents := true) {
		Parents := !!Parents
		if Parents {
			DirCreate(this.Path)
			return
		}
		Parents := this.Parents()
		for Parent in Parents {
			if !FileExist(Parents[-A_Index]) {
				throw OSError(3, -1, '"' Parents[-A_Index] '"')
			}
		}
		DirCreate(this.Path)
	}

	/**
	 * Returns a normalized path by resolving any navigational operators and references (e.g., `.`, `..`).
	 * @returns {Path} - The normalized Path object.
	 */
	NormPath() {
		Chars := DllCall("kernel32.dll\GetFullPathName",
			"Str", this.Path,
			"UInt", 0,
			"Ptr", 0,
			"Ptr", 0,
		)
		VarSetStrCapacity(&NormPath := "", Chars - 1)
		DllCall("kernel32.dll\GetFullPathName",
			"Str", this.Path,
			"UInt", Chars,
			"Str", NormPath,
			"Ptr", 0
		)
		return Path(NormPath)
	}

	/**
	 * Opens the file represented by the Path object with the given flags and encoding.
	 * @param {String} Flags - The flags that specify the actions to be performed on the file. These flags are the same as `FileOpen()`.
	 * @param {String} [Encoding] - The encoding to be used for reading or writing the file.
	 * * *If omitted, the default encoding (as set by `FileEncoding()` or CP0 otherwise) will be used.*
	 * @returns {File} - The File object representing the opened file.
	 * @throws {OSError} - If the file does not exist.
	 * @throws {Error} - If the Path object points to a directory.
	 */
	Open(Flags, Encoding?) {
		if !this.Exists {
			throw OSError(2, -1, '"' this.Path '"')
		}
		if !this.IsFile {
			throw Error("Path points to a directory.", -1, '"' this.Path '"')
		}
		return FileOpen(this.Path, Flags, !IsSet(Encoding) ? "" : Encoding)
	}

	/**
	 * Retrieves an array of parent directories represented by the Path object.
	 * @returns {Array} - An array containing the parent directories of the current Path object.
	 */
	Parents() {
		Parents := Array()
		Parent := this.Path
		while DllCall("shlwapi.dll\PathRemoveFileSpec", "Str", Parent) {
			Parents.Push(Parent)
		}
		return Parents
	}

	/**
	 * Reads the content of the file represented by the Path object.
	 * @param {String} [Encoding=A_FileEncoding] - The encoding to use for reading the file.
	 * * *Specify any of the encoding names accepted by `FileEncoding()` or `RAW` (case-insensitive) to read the file's content as raw binary data.*
	 * @returns {Buffer|String} - If the `Encoding` parameter includes the `RAW` keyword, this function returns a `Buffer` object;
	 * otherwise, it retrieves the content of the file as a string.
	 * @throws {ValueError} - If the `Encoding` parameter is invalid.
	 * @throws {OSError} - If the file does not exist.
	 * @throws {Error} - If the path points to a directory.
	 */
	Read(Encoding := A_FileEncoding) {
		if !RegExMatch(Encoding, "i)^(\d+|CP\d+|RAW|UTF-(?:8|16)(?:-RAW)?)$") {
			throw ValueError("Parameter #1 of " A_ThisFunc " is invalid.", -1, '"' Encoding '"')
		}
		if !this.Exists {
			throw OSError(2, -1, '"' this.Path '"')
		}
		if !this.IsFile {
			throw Error("Path points to a directory.", -1, '"' this.Path '"')
		}
		try {
			return FileRead(this.Path, Encoding)
		}
		catch MemoryError {
			; File sizes larger than 4Gib (Gibibyte) are not supported, manually increase memory size.
			if this.Size > 1024 ** 3 * 4 {
				Encoding := Encoding " M" this.Size / 1024 ** 2
			}
		}
		return FileRead(this.Path, Encoding)
	}

	/**
	 * Renames the file or directory represented by the Path object.
	 * @param {Path|String} Target - The new path or name for the file or directory.
	 * @param {Boolean} [Overwrite=false] - If 1 or `true`, overwrite existing files or directories at the target location.
	 * @returns {Path} - The renamed Path object.
	 * @throws {OSError} - If the path does not exist.
	 */
	Rename(Target, Overwrite := false) {
		if !this.Exists {
			throw OSError(3, -1, '"' this.Path '"')
		}
		CurrentWorkingDir := A_WorkingDir
		Overwrite := !!Overwrite
		SetWorkingDir(this.Parent)
		if Type(Target) != "Path" {
			Target := Path(Target)
		}
		if this.IsFile {
			FileMove(this.Path, Target.Path, Overwrite)
		}
		if this.IsDir {
			DirMove(this.Path, Target.Path, Overwrite ? 2 : 0)
		}
		SetWorkingDir(CurrentWorkingDir)
		return Target
	}

	/**
	 * Removes the directory.
	 * @param {Boolean} [Recurse=false] - If 1 or `true`, remove the directory and its contents recursively.
	 * @throws {OSError} - If the path does not exist or if an error occurs during deletion.
	 * @throws {Error} - If the path points to a file.
	 */
	RmDir(Recurse := false) {
		if !this.Exists {
			throw OSError(3, -1, '"' this.Path '"')
		}
		if !this.IsDir {
			throw Error("Path points to a file.", -1, '"' this.Path '"')
		}
		Recurse := !!Recurse
		try {
			DirDelete(this.Path, Recurse)
		}
		catch Error {
			throw OSError(145, -1, '"' this.Path '"')
		}
	}

	/**
	 * Updates the access time and modification time of the file, or creates a new file.
	 * @param {String} [Time=A_Now] - The new date and time represented as all or the leading part of a `YYYYMMDDHH24MISS` date/time format.
	 * @throws {ValueError} - If the provided date/time format is invalid.
	 */
	Touch(Time := A_Now) {
		if StrLen(Time) < 4 {
			throw ValueError("The date/time format is invalid.", -1, '"' Time '"')
		}
		if this.IsFile {
			this.ATime := Time
			this.MTime := Time
			return
		}
		; Checks if the the path is a file AND doesn't exist in addition to ensuring it isn't a directory.
		if !this.IsDir {
			FileAppend("", this.Path)
		}
	}

	/**
	 * Translates a shell-style pattern into a regular expression pattern.
	 * @param {String} Pattern - The shell-style pattern to translate.
	 * @returns {String} - The translated regular expression pattern.
	 * @throws {ValueError} - If the character class range is out of order.
	 */
	static Translate(Pattern) {
		static CharMap := Map(
			"`s", "\ ",
			"\", "\\",
			"-", "\-",
			"^", "\^",
			"$", "\$",
			".", "\.",
			"|", "\|",
			"?", ".",
			"+", "\+",
			"*", "\*",
			"(", "\(",
			")", "\)",
			"[", "\[",
			"]", "\]",
			"{", "\{",
			"}", "\}"
		)
		Translated := []
		while Pattern {
			Translated.Push("\A")
			while RegExMatch(Pattern, "(\[.*?\])+?", &Match) {
				Str := SubStr(Pattern, 1, Match.Pos() - 1)
				Pattern := StrReplace(Pattern, Str, "", false, &Count, 1)
				Chars := StrSplit(Str)
				; Handle all escape characters prior-to any character class ranges, but not any character class ranges.
				loop Chars.Length {
					Char := Chars[A_Index]
					; Handle any wildcards before they are escaped as an asterisk literal.
					if Char = "*" {
						Chars[A_Index] := ".*?"
						continue
					}
					Chars[A_Index] := CharMap.Has(Char) ? CharMap.Get(Char) : Char
				}
				Translated.Push(Chars*)
				; Begin handling character class ranges.
				Str := SubStr(Pattern, 1, Match.Len())
				MsgBox(Str)
				Pattern := StrReplace(Pattern, Str, "", false, &Count, 1)
				Chars := StrSplit(Str)
				loop Chars.Length - 1 {
					if Chars.Length < 3 || A_Index = 1 {
						continue
					}
					Char := Chars[A_Index]
					if Char = "!" {
						Chars[A_Index] := "^"
						continue
					}
					if char = "-" {
						if Ord(Chars[A_Index - 1]) > Ord(Chars[A_Index + 1]) {
							throw ValueError(
								"Character class range is out of order.",
								-1,
								'"' Chars[A_Index - 1] '-' Chars[A_Index + 1] '"'
							)
						}
						continue
					}
					Chars[A_Index] := CharMap.Has(Char) ? CharMap.Get(Char) : Char
				}
				Translated.Push(Chars*)
			}
			; Handle the remaining pattern after all character class ranges have been dealt with.
			Str := SubStr(Pattern, 1)
			Pattern := StrReplace(Pattern, Str)
			Chars := StrSplit(Str)
			; Handle all escape characters after any/all character class ranges.
			loop Chars.Length {
				Char := Chars[A_Index]
				; Handle any wildcards before they are escaped as an asterisk literal.
				if Char = "*" {
					Chars[A_Index] := ".*"
					continue
				}
				Chars[A_Index] := CharMap.Has(Char) ? CharMap.Get(Char) : Char
			}
			Translated.Push(Chars*)
		}
		Translated.Push("\Z")
		; Convert the Translated array to a string.
		loop Translated.Length {
			if Type(Translated[A_Index]) != "Array" {
				continue
			}
			for Value in Translated[A_Index] {
				Str .= Value
			}
			Translated[A_Index] := Str
		}
		for Value in Translated {
			Pattern .= Value
		}
		return Pattern
	}

	/**
	 * Deletes the file or symbolic link represented by the Path object.
	 * @throws {OSError} - If the path does not exist.
	 * @throws {Error} - If the path points to a directory.
	 */
	Unlink() {
		if !this.Exists {
			throw OSError(2, -1, '"' this.Path '"')
		}
		if !this.IsFile {
			throw Error("Path points to a directory.", -1, '"' this.Path '"')
		}
		FileDelete(this.Path)
	}

	/**
	 * Writes data to a file.
	 * @param {String|Buffer} Data - The data to be written to the file.
	 * @param {String} [Encoding=A_FileEncoding] - The encoding format for the file.
	 * @throws {ValueError} - If the `Encoding` parameter is invalid.
	 * @throws {Error} - If the path points to a directory.
	 */
	Write(Data, Encoding := A_FileEncoding) {
		if !RegExMatch(Encoding, "i)^(`n|CP\d+|RAW|UTF-(?:8|16)(?:-RAW)?)$") {
			throw ValueError("Parameter #1 of " A_ThisFunc " is invalid.", -1, '"' Encoding '"')
		}
		if !this.IsFile {
			throw Error("Path points to a directory.", -1, '"' this.Path '"')
		}
		if this.Exists {
			this.Unlink()
		}
		FileAppend(Data, this.Path, Encoding)
	}

	/**
	 * Gets the URI (Uniform Resource Identifier) representation of the file or directory path represented by the Path object.
	 * @property {String} AsURI - The URI representation of the file or directory path.
	 */
	AsURI {
		Get  {
			VarSetStrCapacity(&Uri := "", INTERNET_MAX_URL_LENGTH := 2083)
			DllCall("shlwapi.dll\UrlCreateFromPath",
				"Ptr", StrPtr(this.Path), ; pszPath
				"Str", Uri, ; pszUrl
				"UInt*", INTERNET_MAX_URL_LENGTH, ; *pcchUrl
				"UInt", 0 ; dwFlags
			)
			return Uri
		}
	}

	/**
	 * Gets or sets the last access time of the file or directory represented by the Path object.
	 * @property {String} Get - Retrieves the last access time.
	 * @property {Integer|String} Set - Sets the last access time.
	 * @throws {TypeError} - If the parameter is not an integer or string.
	 * @throws {ValueError} - If the date/time format is invalid.
	 */
	ATime {
		Get => FileGetTime(this.Path, "A")
		Set {
			if Type(value) != "Integer" && Type(value) != "String" {
				throw TypeError("Parameter requires an Integer, or String but received a " Type(value) ".", -1, '"' value '"')
			}
			if StrLen(value) < 4 {
				throw ValueError("The date/time format is invalid.", -1, '"' value '"')
			}
			FileSetTime(value, this.Path, "A", this.IsDir ? "D" : "F")
		}
	}

	/**
	 * Gets or sets the creation time of the file or directory represented by the Path object.
	 * @property {String} Get - Retrieves the creation time.
	 * @property {Integer|String} Set - Sets the creation time.
	 * @throws {TypeError} - If the parameter is not an integer or string.
	 * @throws {ValueError} - If the date/time format is invalid.
	 */
	CTime {
		Get => FileGetTime(this.Path, "C")
		Set {
			if Type(value) != "Integer" && Type(value) != "String" {
				throw TypeError("Parameter requires an Integer, or String but received a " Type(value) ".", -1, '"' value '"')
			}
			if StrLen(value) < 4 {
				throw ValueError("The date/time format is invalid.", -1, '"' value '"')
			}
			FileSetTime(value, this.Path, "C", this.IsDir ? "D" : "F")
		}
	}

	/**
	 * Gets the drive letter or name represented by the Path object.
	 * @property {String} Get - The the drive letter or name, if any.
	 */
	Drive {
		Get {
			Drive := this.Path
			if DllCall("shlwapi.dll\PathStripToRoot", "Str", Drive) {
				return RTrim(Drive, "\")
			}
		}
	}

	/**
	 * Indicates whether the file or directory at the specified path exists.
	 * @property {Boolean} Exists - 1 or `true` if the file or directory exists; otherwise, 0 or `false`.
	 */
	Exists {
		Get {
			return FileExist(this.Path) ? true : false
		}
	}

	/**
	 * Indicates whether the Path object represents an absolute path.
	 * @property {Boolean} IsAbsolute - 1 or `true` if the  Path object is an absolute path; otherwise, 0 or `false`.
	 */
	IsAbsolute {
		Get {
			if this.Root {
				return true
			}
			return false
		}
	}

	/**
	 * Indicates whether the Path object represents a directory.
	 * @property {Boolean} IsDir - 1 or `true` if the Path object represents a directory; otherwise, 0 or `false`.
	 */
	IsDir {
		Get {
			Attributes := FileExist(this.Path)
			if !Attributes {
				return false
			}
			return InStr(Attributes, "D") ? true : false
		}
	}

	/**
	 * Indicates whether the Path object represents a file.
	 * @property {Boolean} IsFile - 1 or `true` if the Path object represents a file; otherwise, 0 or `false`.
	 */
	IsFile {
		Get {
			Attributes := FileExist(this.Path)
			if !Attributes {
				return false
			}
			return InStr(Attributes, "D") ? false : true
		}
	}

	/**
	 * Indicates whether the Path object represents a symbolic link.
	 * @property {Boolean} IsFile - 1 or `true` if the Path object represents a symbolic link; otherwise, 0 or `false`.
	 */
	IsSymLink {
		Get {
			Attributes := FileExist(this.Path)
			if !Attributes {
				return false
			}
			return InStr(Attributes, "L") ? true : false
		}
	}

	/**
	 * Gets or sets the last modified time of the file or directory represented by the Path object.
	 * @property {String} Get - Retrieves the last modified time.
	 * @property {Integer|String} Set - Sets the last modified time.
	 * @throws {TypeError} - If the parameter is not an integer or string.
	 * @throws {ValueError} - If the date/time format is invalid.
	 */
	MTime {
		Get => FileGetTime(this.Path, "M")
		Set {
			if Type(value) != "Integer" && Type(value) != "String" {
				throw TypeError("Parameter requires an Integer, or String but received a " Type(value) ".", -1, '"' value '"')
			}
			if StrLen(value) < 4 {
				throw ValueError("The date/time format is invalid.", -1, '"' value '"')
			}
			FileSetTime(value, this.Path, "M", this.IsDir ? "D" : "F")
		}
	}

	/**
	 * Gets the name of the file or directory represented by the Path object.
	 * @property {String} Name - The name of the file or directory.
	 */
	Name {
		Get => DllCall("shlwapi.dll\PathFindFileName", "Ptr", StrPtr(this.Path), "Str")
	}

	/**
	 * Gets the owner of the file or directory represented by the Path object.
	 * @property {String} Owner - The owner of the file or directory.
	 */
	Owner {
		Get {
			Shell := ComObject("Shell.Application")
			FolderObj := Shell.NameSpace(this.Parent)
			FileItemObj	:= FolderObj.ParseName(this.Name)
			Detail := FolderObj.GetDetailsOf(FileItemObj, 10)
			if Detail != "Owner" {
				return StrReplace(Detail, A_ComputerName "\") ; Result includes host name, remove it.
			}
		}
	}

	/**
	 * Gets the immediate parent directory of the file or directory represented by the Path object.
	 * @property {String} Parent - The immediate parent directory path.
	 */
	Parent {
		Get => this.Parents()[1]
	}

	/**
	 * Gets an array of individual parts in the file or directory path.
	 * @property {String[]} Parts - An array of path components.
	 */
	Parts {
		Get {
			return StrSplit(this.Path, "\")
		}
	}

	/**
	 * Gets the root portion of the path represented by the Path object.
	 * @property {String} Root - The root of the path.
	 */
	Root {
		Get {
			Root := this.Path
			if DllCall("shlwapi.dll\PathStripToRoot", "Str", Root) {
					return Root
			}
		}
	}

	/**
	 * Gets the size of the file or folder represented by the Path object.
	 * @property {Integer} Size - The size of the file or folder in bytes.
	 */
	Size {
		Get {
			if this.IsDir {
				Size := Format("{:d}", ComObject("Scripting.FileSystemObject").GetFolder(this.Path).Size)
			}
			if this.IsFile {
				Size := FileGetSize(this.Path)
			}
			return Size
		}
	}

	/**
	 * Gets the stem (file or folder name without extension) from the path represented by the Path object.
	 * @property {String} Stem - The stem of the file or folder.
	 */
	Stem {
		Get {
			Stem := this.Path
			DllCall("shlwapi.dll\PathStripPath", "Str", Stem)
			DllCall("shlwapi.dll\PathRemoveExtension", "Str", Stem)
			return Stem
		}
	}

	/**
	 * Gets the suffix (file extension) from the path represented by the Path object.
	 * @property {String} Suffix - The suffix of the file.
	 */
	Suffix {
		Get => DllCall("shlwapi.dll\PathFindExtension", "Ptr", StrPtr(this.Path), "Str")
	}

	/**
	 * Gets an array of all suffixes (file extensions) from the path represented by the Path object.
	 * @property {String[]} Suffixes - An array of file suffixes.
	 */
	Suffixes {
		Get {
			Path := this.Path
			Suffixes := Array()
			while Suffix := DllCall("shlwapi.dll\PathFindExtension", "Str", Path, "Str") {
				Suffixes.Push(Suffix)
				Path := SubStr(Path, 1, -StrLen(Suffix))
			}
			return Suffixes
		}
	}

	/**
	 * Gets the type of the file or directory represented by the Path object.
	 * @property {String} Type - The type of the file or directory (e.g., *Text Document*, *File Folder*, *JPEG Image*).
	 */
	Type {
		Get {
			FileSystemObj := ComObject("Scripting.FileSystemObject")
			if this.IsDir {
				Type := FileSystemObj.GetFolder(this.Path).Type
			}
			if this.IsFile {
				Type := FileSystemObj.GetFile(this.Path).Type
			}
			return Type
		}
	}
}
