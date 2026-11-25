# DIFFERENZE — cosa cambia rispetto alle versioni d'origine

Nucleo v0.1.0, 25/11/2026. Per ogni funzione: la fonte (file e commit), cosa è rimasto uguale, cosa è cambiato e perché.

## which_absolute — `nucleo/programs.py`

Fonte: cryptovalid, commit f7883c9 (0.29.0 in preparazione, non ancora rilasciata il 25/11/2026), `verifier.py` riga 429
(`which`).

Uguale: si scarta una risposta di `shutil.which` che non è assoluta e si cercano solo le cartelle assolute di PATH
(su Windows con le estensioni di PATHEXT); il file deve esistere ed essere eseguibile.

Cambiato:

1. **Solo un nome nudo.** `which_absolute("./openssl")`, `"a/b"`, `"a\\b"`, `""`, `"."`, `".."`, un NUL e (su Windows) i
   due punti danno `ValueError`; un tipo diverso da `str` dà `TypeError`. In f7883c9 un nome con un separatore passava a
   `shutil.which`, che lo cerca relativo alla cartella corrente: la regola «mai la cartella corrente» si aggirava
   passando un percorso. Chiuso per costruzione: un nome di programma, e basta.
2. **Windows, nome con estensione.** `which_absolute("tool.exe")` cerca `tool.exe` così com'è, come fa `shutil.which`.
   In f7883c9, scartata la risposta relativa, il secondo giro cercava `tool.exe.COM`, `tool.exe.EXE`… e non trovava
   niente. Il test `test_a_name_with_its_extension` lo misura sul codice vecchio (controllo positivo, solo Windows).
3. **Windows, assoluto vuol dire con il disco.** Una voce di PATH come `\tools` è una cartella del disco CORRENTE
   (quello della cartella corrente). `ntpath.isabs("\\tools")` risponde `True` fino a Python 3.12 e `False` da 3.13
   (misurato con `ntpath` su 3.9, 3.11 e 3.13): in f7883c9 la stessa voce era cercata o no a seconda del Python. Qui una
   voce, e la risposta di `shutil.which`, valgono solo con disco o con server e condivisione (`C:\…`,
   `\\server\share\…`). La regola è scritta nel nucleo e non chiesta a `ntpath`: anche `ntpath.splitdrive` cambia con il
   Python (`\\server` senza condivisione ha un «disco» da 3.11 e non in 3.9; il 25/11/2026, su 42 133 percorsi generati, `isabs` più
   `splitdrive` davano 4 000 risposte diverse tra 3.9 e 3.11 e altre tra 3.11 e 3.12; la regola del nucleo nessuna).

## run_program — `nucleo/programs.py`

Nuova: nelle fonti non c'era una funzione unica (cryptovalid `_run_openssl`, ap2 `subprocess.run(cmd…)` sparsi).
argv[0] è un nome nudo cercato con `which_absolute`; niente shell; `env` obbligatorio e usato da solo (anche `{}`);
`timeout` obbligatorio, maggiore di 0 e al più 2 000 000 secondi (circa 23 giorni: `poll()` prende al massimo 2^31−1
millisecondi; infinito e 1e30 → `ValueError`, non un `OverflowError` dall'interno di subprocess); stdin vuoto
(`DEVNULL`) se non si passa `input`, così il programma non legge lo stdin del chiamante; uscita ed errori catturati
come bytes. Programma assente → `FileNotFoundError`. Il codice di uscita lo legge il chiamante.

**Windows, file batch.** Un programma trovato come `.bat` o `.cmd` è un `ValueError`: il sistema lo passa a `cmd.exe`,
che legge gli argomenti con le regole di una shell anche con `shell=False` (documentazione di `subprocess`, «Security
Considerations», letta il 25/11/2026 per Python 3.9, 3.13 e main). `which_absolute` lo nomina ancora, perché PATHEXT
lo comprende; è `run_program` che non lo avvia.

Nota per Windows: con `env={}` molti programmi non partono (Python stesso chiede `SystemRoot`); spetta al chiamante
mettere nell'ambiente ciò che serve, per nome.

## create_exclusive / create_private / private_tmpdir — `nucleo/files.py`

Fonti: cryptovalid `verifier.create_private` (commit 809be6a, identica in f7883c9, `verifier.py` riga 448) e
`owner_only` (riga 369); ap2-evidence-pack `_create_exclusive` e `_private_tmpdir` (commit df398fa e 5df7cb4,
`ap2_evidence.py` righe 2404 e 2424 in 5df7cb4; 2404 e 2423 in df398fa).

Uguale in entrambe e qui: nome casuale `prefisso + 16 esadecimali (+ suffisso)`; `O_CREAT|O_EXCL|O_NOFOLLOW|O_BINARY`;
si ritenta solo `FileExistsError`, al massimo 64 volte; ogni altro `OSError` subito; cartelle `mkdir(…, 0o700)`.

Dove le due versioni differivano, la scelta:

| Punto | cryptovalid | ap2-evidence-pack | Nucleo | Perché |
|---|---|---|---|---|
| Apertura | `O_RDWR` | `O_WRONLY` | `O_RDWR` | chi scrive può anche rileggere (cryptovalid lo usa); nessun costo |
| `O_CLOEXEC` | no | sì | sì | il descrittore non passa ai programmi lanciati dopo |
| Mode del file | sempre 0600 | parametro (0666 per il pacchetto, 0600 per stamp) | `create_exclusive(mode=0o600)` con parametro; `create_private` = 0600 | ap2 ha bisogno di 0666-umask per un file che sostituisce un `open(path,"w")` |
| Nome | `prefisso+hex+suffisso` | `prefisso+hex+".tmp"` | `prefisso+hex+suffisso` | ap2 diventa `suffix=".tmp"`: stesso nome |
| Cartella | `create_private(…, directory=True)`, base obbligatoria | `_private_tmpdir(prefix, base=None)` = `tempfile.gettempdir()` | `private_tmpdir(prefix, base=None)` | una funzione per i file, una per le cartelle, nessun flag |
| Windows | 0600 vale solo come attributo «sola lettura» | idem | `create_private` e `private_tmpdir` impostano la lista d'accesso: una voce, l'utente, controllo totale, niente ereditato (sulla cartella ereditabile, `OICI`) | regola di Roberto 24/11: su Windows l'equivalente dei permessi POSIX è la ACL; viene da `owner_only` di cryptovalid |
| Errori dopo l'apertura | non c'erano passi dopo | idem | se la ACL non si imposta: descrittore chiuso, file o cartella rimossi, errore rilanciato | il descrittore si chiude negli errori |
| Nome già preso, su Windows | `O_EXCL` | idem | anche `lexists` prima di aprire | lì `O_CREAT\|O_EXCL` su un link verso il nulla crea il file a cui punta, e una cartella al nome è `PermissionError` (misurato nella prima CI, run 45583189095, Python 3.9–3.14); il nome ha 64 bit casuali, fra il controllo e l'apertura non è prevedibile |
| Prefisso/suffisso | non controllati | idem | un separatore o un NUL → `ValueError`, niente creato; su Windows anche un nome che il sistema riserva (i due punti, un jolly, un carattere di controllo, punto o spazio finale, un nome di dispositivo prima del primo punto) | `tempfile.mkstemp(prefix="sub/")` crea in un'altra cartella (misurato nel test); su Windows `os.path.join("D:\\dir", "C:nome")` è `C:nome` (la cartella sparisce), `a:nome` è un flusso del file `a`, `NUL.x` è il dispositivo NUL prima di Windows 11; le regole sono quelle di `ntpath.isreserved` di Python 3.13, confrontate nel test su nomi generati |

Mutante sopravvissuto e perché: togliere `O_NOFOLLOW` non fa fallire nessun test, perché con `O_CREAT|O_EXCL`
l'apertura rifiuta già un link nel punto del nome (POSIX lo richiede; Windows non conosce `O_NOFOLLOW`, vedi sopra). Resta come seconda cintura, dichiarata.

## json_loads_bounded — `nucleo/jsonio.py`

Fonte: cryptovalid f7883c9, `verifier.py` righe 1027–1075 (`json_nesting_depth`, `JsonTooDeep`, `JsonTooDeepToRead`,
`json_loads_bounded`, SPEC §30).

Uguale: scansione lineare dei caratteri (stringhe saltate, escape rispettati), bytes decodificati come fa `json.loads`
(`json.detect_encoding`, `surrogatepass`) PRIMA di contare; eccezione `JsonTooDeepToRead` che è insieme `ValueError` e
`RecursionError`.

Cambiato: la profondità massima è il parametro `max_depth` (512 di default, come `MAX_JSON_DEPTH` di cryptovalid);
un valore non intero, negativo o `bool` → `ValueError`. **Lo spazio di pila per il parser è dentro la funzione**
(`_RecursionHeadroom`, da cryptovalid f7883c9 `verifier.py` riga 830, dove lo tenevano i chiamanti): sotto Python
3.9–3.11 i livelli del parser contano sul limite di ricorsione, e un testo di 512 livelli letto da 600 frame di
profondità era un `RecursionError` nudo (3.9 e 3.11) ma era letto sotto 3.13; ora è letto ovunque, e il limite torna
com'era alla fine. Vale fino a 512 livelli: con `max_depth` più alto, oltre 512 decide il parser di ogni Python.
Misurato: la scansione di un testo di ~4 milioni di caratteri alloca meno di 64 KiB (tracemalloc, test
`ConstantMemory`).

## canonical_json — `nucleo/canonical.py`

Due funzioni, ognuna chiamata per nome:

- `canonical_json_sorted_ascii(value)`: `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
  Stessi bytes, su 2000 valori casuali (test generativo), dell'espressione `json.dumps(v, sort_keys=True,
  separators=(",", ":")).encode()` che usano `_canon` di ap2 e `canonical_payload` di cryptovalid (quest'ultima dopo
  aver tolto da una riga `self_hash` e i campi di attestazione: quel passo resta al chiamante).
  **Cambiato:** `allow_nan=False`. La forma di oggi scrive `NaN`/`Infinity`, che non sono JSON (RFC 8259 §6); qui sono
  un `ValueError`. Prima di sostituire una funzione locale va controllato che un NaN non possa arrivarci.
- `canonical_json_jcs(value)`: RFC 8785, da aee-verifier commit 0d8cee1 `aee_verifier/jcs.py`, identica tranne il nome
  (`canonicalize` lì). Interi di modulo ≥ 2^53 rifiutati, NaN/Infinity rifiutati, surrogati spaiati rifiutati.

Attenzione: NON sono la stessa forma di `json.dumps(…, ensure_ascii=False)` né di `json.dumps(…, default=str)`, usate
in altri punti dei lavori: quelle restano dove sono.

## Vettori di RFC 8785

RFC 8785 è nello stream Independent Submission. Le IETF Trust Legal Provisions 5.0 (in vigore dal 25/03/2015, lette il
25/11/2026 su trustee.ietf.org) escludono per quello stream sia la licenza sulle parti (§3.c, per §8.c.iii) sia la
licenza BSD dei code component (§4, per §8.f). Quindi nessun vettore, tabella o esempio dell'RFC sta in questo repository
(il test li trova nel testo ufficiale con tre brevi frasi d'ancoraggio; qui sotto è citata una sola coppia di numeri): il test
`tests/test_vectors_rfc8785.py` legge il file ufficiale (`NUCLEO_RFC8785`, scaricato dalla CI da rfc-editor.org,
sha256 `63d52294…ab240`) ed estrae al momento: tabella dell'Appendice B (26 righe: 24 numeri, NaN e Infinity), esempio
del §3.2.2 con i suoi 118 bytes del §3.2.4, vettore d'ordinamento del §3.2.3. Differenza con la fonte: aee-verifier
teneva 23 numeri dell'Appendice B nel test; mancava `43143ff3c1cb0959 → 1424953923781206.2` (arrotondamento al pari),
ora controllato.

## nucleo_sync.py — chiuso anche contro link, pipe e cartelle che nascondono una copia

Nuovo in questo repository (nessuna fonte). Dopo la revisione del 25/11/2026:

- `copy` non scrive mai attraverso un link: ogni file è scritto accanto (`create_exclusive`) e spostato al suo posto
  (`os.replace`). Prima, in una copia esistente dove `files.py` o il manifest erano un link, `shutil.copyfile` scriveva
  il file del nucleo nel bersaglio del link, anche fuori dal repository (misurato), e finiva con un traceback.
  Ogni errore di `copy` è ora un errore d'uso (exit 2) con il suo nome; una cartella che tiene qualcosa che non è del
  nucleo è rifiutata prima di scrivere un file.
- `check` rifiuta un manifest che non è un file regolare PRIMA di aprirlo (una pipe a quel nome non finiva mai), trova
  il manifest anche se è una cartella o ha altre maiuscole, e rifiuta ciò che non può controllare: una cartella che non
  si può elencare (`folder_unreadable`), una cartella-link con un manifest dentro (`copy_behind_a_link`). Prima, con
  una copia buona accanto, usciva 0.
- Non entra, quindi non controlla: cartelle nascoste, `__pycache__`, `node_modules`. Una cartella senza manifest non è
  una copia. Il contenuto di `__pycache__` dentro una copia non è controllato.
- Il commit stampato è quello che il manifest dichiara: `check` confronta i file con il nucleo, non il commit.
- I nomi stampati (chiavi del manifest, file, cartelle) stanno su una riga: un a-capo in un nome non scrive una riga
  `OK` finta, un surrogato spaiato non ferma la stampa.
