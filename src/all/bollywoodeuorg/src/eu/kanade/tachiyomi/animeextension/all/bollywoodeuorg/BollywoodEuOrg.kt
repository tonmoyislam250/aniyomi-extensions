package eu.kanade.tachiyomi.animeextension.all.bollywoodeuorg

import android.app.Application
import android.content.SharedPreferences
import android.util.Base64
import androidx.preference.ListPreference
import androidx.preference.PreferenceScreen
import eu.kanade.tachiyomi.animesource.ConfigurableAnimeSource
import eu.kanade.tachiyomi.animesource.model.AnimeFilter
import eu.kanade.tachiyomi.animesource.model.AnimeFilterList
import eu.kanade.tachiyomi.animesource.model.AnimesPage
import eu.kanade.tachiyomi.animesource.model.SAnime
import eu.kanade.tachiyomi.animesource.model.SEpisode
import eu.kanade.tachiyomi.animesource.model.Video
import eu.kanade.tachiyomi.animesource.online.AnimeHttpSource
import eu.kanade.tachiyomi.lib.synchrony.Deobfuscator
import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.network.POST
import eu.kanade.tachiyomi.util.asJsoup
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.CacheControl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import rx.Observable
import uy.kohesive.injekt.Injekt
import uy.kohesive.injekt.api.get
import uy.kohesive.injekt.injectLazy
import java.lang.Exception
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class BollywoodEuOrg : ConfigurableAnimeSource, AnimeHttpSource() {

    override val name = "bollywood.eu.org"

    override val baseUrl = "https://bollywood.eu.org"

    override val lang = "all"

    override val supportsLatest = false

    private val json: Json by injectLazy()

    override val client = network.cloudflareClient

    private val preferences: SharedPreferences by lazy {
        Injekt.get<Application>().getSharedPreferences("source_$id", 0x0000)
    }

    // Stolen from AniWatch
    private val noCacheClient = OkHttpClient().newBuilder()
        .cache(null)
        .build()

    private val apiHeaders = headers.newBuilder()
        .add("Accept", "application/json, text/javascript, */*; q=0.01")
        .add("Host", "api.themoviedb.org")
        .add("Origin", baseUrl)
        .add("Referer", "$baseUrl/")
        .build()

    // ============================ Initializers ============================

    private val jsFile by lazy {
        val scriptSrc = client.newCall(
            GET(baseUrl, headers),
        ).execute().asJsoup().selectFirst("script[src*=app.min.js]")!!.attr("abs:src")

        val js = noCacheClient.newCall(
            GET(scriptSrc, headers, cache = CACHE_CONTROL),
        ).execute().body.string()

        Deobfuscator.deobfuscateScript(js) ?: throw Exception("JavaScript deobfuscation failed!")
    }

    private val tmdbApiKey by lazy {
        Regex("apiKey ?= ?['\"]([^'\"]+)['\"]").find(jsFile)?.groupValues?.get(1) ?: throw Exception("Failed to extract tmdb API key")
    }

    private val tmdbUrl by lazy {
        Regex("apiUrl ?= ?['\"]([^'\"]+)['\"]").find(jsFile)?.groupValues?.get(1) ?: throw Exception("Failed to extract tmdb API key")
    }

    private val posterPath by lazy {
        jsFile.substringAfter(".poster_path").substringAfter("'").substringBefore("'")
    }

    private val videosFunc by lazy {
        jsFile.substringAfter("function getFileFromDrive").substringBefore("Authorization")
    }

    private val secretIv by lazy {
        val ivStr = jsFile.substringAfter("const encrypt_iv = new Uint8Array(").substringBefore(")")
            .replace(",\n", "\n")
        val encryptIv = json.decodeFromString<List<Int>>(ivStr).map {
            it.toByte()
        }.toByteArray()
        IvParameterSpec(encryptIv)
    }

    private val geoLocationJs by lazy {
        val doc = client.newCall(
            GET(baseUrl, headers),
        ).execute().asJsoup()
        val jsFile = doc.selectFirst("script[src*=geolocation]")!!.attr("abs:src")
        noCacheClient.newCall(
            GET(jsFile, headers, cache = CACHE_CONTROL),
        ).execute().body.string()
    }

    // ============================== Popular ===============================

    override fun popularAnimeRequest(page: Int): Request {
        val url = buildString {
            append(tmdbUrl)
            append(getPath("loadTrending"))
            append(tmdbApiKey)
            append("&page=")
            append(page)
        }
        return GET(url, headers = apiHeaders)
    }

    override fun popularAnimeParse(response: Response): AnimesPage {
        val data = response.parseAs<TmdbResponse>()

        val animeList = data.results.map { ani ->
            val name = ani.title ?: ani.name ?: "Title N/A"

            SAnime.create().apply {
                title = name
                url = LinkData(ani.id, ani.media_type).toJsonString()
                thumbnail_url = ani.poster_path?.let { posterPath + it } ?: ""
            }
        }

        return AnimesPage(animeList, data.page < data.total_pages)
    }

    // =============================== Latest ===============================

    override fun latestUpdatesRequest(page: Int): Request = throw Exception("Not used")

    override fun latestUpdatesParse(response: Response): AnimesPage = throw Exception("Not used")

    // =============================== Search ===============================

    override fun searchAnimeRequest(page: Int, query: String, filters: AnimeFilterList): Request {
        val filterList = if (filters.isEmpty()) getFilterList() else filters
        val typeFilter = filterList.find { it is TypeFilter } as TypeFilter
        val categoryFilter = filterList.find { it is CategoryFilter } as CategoryFilter

        return when {
            query.isNotBlank() -> {
                val url = buildString {
                    append(tmdbUrl)
                    append(getPath("searchSystem"))
                    append(typeFilter.toUriPart())
                    append("?api_key=$tmdbApiKey")
                    append("&page=$page")
                    append("&sort_by=popularity.desc")
                    append("&query=$query")
                }

                GET(url, headers = apiHeaders)
            }
            categoryFilter.state != 0 -> {
                val selected = categoryFilter.toUriPart()
                val path = if (selected.contains("release_date")) getPath("loadMovies") else getPath("loadTVShows")
                val url = buildString {
                    append(tmdbUrl)
                    append(path)
                    append(tmdbApiKey)
                    append("&sort_by=popularity.desc")
                    append(selected)
                    append(DATE_FORMATTER.format(Date()))
                    append("&page=$page")
                    append("&_=${System.currentTimeMillis()}")
                }
                GET(url, headers = apiHeaders)
            }
            else -> throw Exception("Either search or select a category")
        }
    }

    override fun searchAnimeParse(response: Response): AnimesPage {
        val type = if (response.request.url.encodedPath.contains("movie")) "movie" else "tv"
        val data = response.parseAs<TmdbResponse>()

        val animeList = data.results.map { ani ->
            val name = ani.title ?: ani.name ?: "Title N/A"

            SAnime.create().apply {
                title = name
                url = LinkData(ani.id, type).toJsonString()
                thumbnail_url = ani.poster_path?.let { posterPath + it } ?: ""
            }
        }

        return AnimesPage(animeList, data.page < data.total_pages)
    }

    // ============================== Filters ===============================

    override fun getFilterList(): AnimeFilterList = AnimeFilterList(
        TypeFilter(),
        AnimeFilter.Header("Note: Categories will ignore search & other filters"),
        CategoryFilter(),
    )

    private class TypeFilter : UriPartFilter(
        "Search type",
        arrayOf(
            Pair("Movies", "movie"),
            Pair("TV Shows", "tv"),
        ),
    )

    private class CategoryFilter : UriPartFilter(
        "Category",
        arrayOf(
            Pair("<select>", ""),

            Pair("Bollywood", "&region=IN&with_original_language=hi&release_date.lte="),
            Pair("Hollywood", "&region=US&with_original_language=en&release_date.lte="),
            Pair("Indian TV", "&with_original_language=hi&air_date.lte="),
            Pair("English TV", "&with_original_language=en&air_date.lte="),

            Pair("Hindi", "&region=IN&with_original_language=hi&release_date.lte="),
            Pair("Tamil", "&region=IN&with_original_language=ta&release_date.lte="),
            Pair("Telugu", "&region=IN&with_original_language=te&release_date.lte="),
            Pair("Kannada", "&region=IN&with_original_language=kn&release_date.lte="),
            Pair("Malayalam", "&region=IN&with_original_language=ml&release_date.lte="),
            Pair("Bengali", "&region=IN&with_original_language=bn&release_date.lte="),
            Pair("Punjabi", "&region=IN&with_original_language=pa&release_date.lte="),
            Pair("Marathi", "&region=IN&with_original_language=mr&release_date.lte="),
            Pair("Gujarati", "&region=IN&with_original_language=gu&release_date.lte="),
            Pair("Urdu", "&region=IN&with_original_language=ur&release_date.lte="),

            Pair("Mandarin Chinese", "&region=CN&with_original_language=zh&release_date.lte="),
            Pair("Spanish", "&region=ES&with_original_language=es&release_date.lte="),
            Pair("Arabic", "&region=EG&with_original_language=ar&release_date.lte="),
            Pair("Portuguese", "&region=PT&with_original_language=pt&release_date.lte="),
            Pair("Russian", "&region=RU&with_original_language=ru&release_date.lte="),
            Pair("Japanese", "&region=JP&with_original_language=ja&release_date.lte="),
            Pair("German", "&region=DE&with_original_language=de&release_date.lte="),
            Pair("French", "&region=FR&with_original_language=fr&release_date.lte="),
            Pair("Korean", "&region=KR&with_original_language=ko&release_date.lte="),
            Pair("Italian", "&region=IT&with_original_language=it&release_date.lte="),
        ),
    )

    private open class UriPartFilter(displayName: String, val vals: Array<Pair<String, String>>) :
        AnimeFilter.Select<String>(displayName, vals.map { it.first }.toTypedArray()) {
        fun toUriPart() = vals[state].second
    }

    // =========================== Anime Details ============================

    override fun animeDetailsRequest(anime: SAnime): Request {
        val data = json.decodeFromString<LinkData>(anime.url)

        val funcName = if (data.media_type == "movie") "loadMovieDetails" else "loadTVShowDetails"

        val url = buildString {
            append(tmdbUrl)
            append(getPath(funcName))
            append(data.id)
            append("?api_key=$tmdbApiKey")
            append("&append_to_response=")
            append(
                jsFile.substringAfter(funcName)
                    .substringAfter("append_to_response")
                    .substringAfter("'")
                    .substringBefore("'"),
            )
        }

        return GET(url, headers = apiHeaders)
    }

    override fun animeDetailsParse(response: Response): SAnime {
        val data = response.parseAs<TmdbDetailsResponse>()

        return SAnime.create().apply {
            genre = data.genres?.joinToString(", ") { it.name }
            description = buildString {
                if (data.overview != null) {
                    append(data.overview)
                    append("\n\n")
                }
                if (data.release_date != null) append("Release date: ${data.release_date}")
                if (data.first_air_date != null) append("First air date: ${data.first_air_date}")
                if (data.last_air_date != null) append("Last air date: ${data.last_air_date}")
            }
        }
    }

    // ============================== Episodes ==============================

    override fun episodeListRequest(anime: SAnime): Request = animeDetailsRequest(anime)

    override fun episodeListParse(response: Response): List<SEpisode> {
        val data = response.parseAs<TmdbDetailsResponse>()
        val episodeList = mutableListOf<SEpisode>()

        if (data.title != null) { // movie
            episodeList.add(
                SEpisode.create().apply {
                    name = "Movie"
                    date_upload = parseDate(data.release_date!!)
                    episode_number = 1F
                    url = "${data.title.replace(Regex("[\\(\\)'\"@$:]"), "")} ${data.release_date.substring(0, 4)}"
                },
            )
        } else {
            data.seasons.filter { t -> t.season_number != 0 }.forEach { season ->
                val seasonPath = getPath("loadTVSeasonDetails")
                val seasonsUrl = buildString {
                    append(tmdbUrl)
                    append(seasonPath)
                    append(data.id)
                    append("/season/")
                    append(season.season_number)
                    append("?api_key=$tmdbApiKey")
                    append("&append_to_response=")
                    append(
                        jsFile.substringAfter("loadTVSeasonDetails")
                            .substringAfter("append_to_response")
                            .substringAfter("'")
                            .substringBefore("'"),
                    )
                }
                val seasonsData = client.newCall(
                    GET(seasonsUrl, headers = apiHeaders),
                ).execute().parseAs<TmdbSeasonResponse>()

                seasonsData.episodes.forEach { ep ->

                    val seasonString = season.season_number.toString().padStart(2, '0')
                    val episodeString = ep.episode_number.toString().padStart(2, '0')

                    episodeList.add(
                        SEpisode.create().apply {
                            name = "Season ${season.season_number} Ep. ${ep.episode_number} - ${ep.name}"
                            date_upload = ep.air_date?.let(::parseDate) ?: 0L
                            episode_number = ep.episode_number.toFloat()
                            url = "${data.name!!.replace(Regex("[\\(\\)'\"@$:]"), "")} S${seasonString}E$episodeString"
                        },
                    )
                }
            }
        }

        return episodeList.reversed()
    }

    // ============================ Video Links =============================

    override fun fetchVideoList(episode: SEpisode): Observable<List<Video>> {
        val videoList = mutableListOf<Video>()

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        val expiry = ((System.currentTimeMillis() + 300000) / 1000)
            .toString().toByteArray()

        val key = videosFunc.substringAfter("encode('").substringBefore("'").toByteArray()
        val secretKey = SecretKeySpec(key, "AES")

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, secretIv)
        val encrypted = Base64.encodeToString(cipher.doFinal(expiry), Base64.NO_WRAP)

        // Make POST request
        val postBody = buildJsonObject {
            put("query", episode.url)
        }.toString().toRequestBody("application/json".toMediaType())

        val postUrl = videosFunc.substringAfter("fetch('").substringBefore("'")
        val postHeaders = headers.newBuilder()
            .add("Accept", "*/*")
            .add("Authorization", "Bearer $encrypted")
            .add("Content-Type", "application/json")
            .add("Host", postUrl.toHttpUrl().host)
            .add("Origin", baseUrl)
            .add("Referer", "$baseUrl/")
            .build()

        var driveData = client.newCall(
            POST(postUrl, body = postBody, headers = postHeaders),
        ).execute().parseAs<List<DriveResponseObject>>()

        if (Regex(" S\\d+E\\d+\$").find(episode.url) != null) {
            driveData = driveData.filter { it.name.contains(episode.url.substringAfterLast(" "), true) }
        }

        videoList.addAll(
            decryptDriveResponse(driveData),
        )

        require(videoList.isNotEmpty()) { "Failed to fetch videos" }
        return Observable.just(videoList.sort())
    }

    private fun decryptDriveResponse(driveData: List<DriveResponseObject>): List<Video> {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val newSecretKeyStr = jsFile.substringAfter("function decryptData")
            .substringAfter("encode('").substringBefore("'")
            .toByteArray()

        val getDriveFunc = jsFile.substringAfter("function getFileFromDrive")
            .substringBefore("function")

        val secretKey = SecretKeySpec(newSecretKeyStr, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, secretIv)

        return driveData.map { vid ->
            val decrypted = cipher.doFinal(Base64.decode(vid.id, Base64.DEFAULT))
            val (signature, expiry) = signRequest(String(decrypted))

            val pass1 = getDriveFunc.substringAfter("CryptoJS.AES.encrypt")
                .substringAfter("'")
                .substringBefore("'")
            val pass2 = getDriveFunc.substringAfter("CryptoJS.AES.encrypt")
                .substringAfter("CryptoJS.AES.encrypt")
                .substringAfter("'")
                .substringBefore("'")

            val encryptedData = json.decodeFromString<List<String>>(
                encryptStrings(String(decrypted), pass1, expiry, pass2),
            ).map {
                encodeBase64(it.toByteArray())
            }

            val serviceName = geoLocationJs.substringAfter("service_name")
                .substringAfter("\"")
                .substringBefore("\"")

            val workerName = geoLocationJs.substringAfter("arrayofworkers")
                .substringAfter("\"")
                .substringBefore("\"")

            val url = buildString {
                append("https://")
                append(serviceName)
                append(".")
                append(workerName)
                append(".workers.dev/download.aspx")
            }.toHttpUrl().newBuilder().apply {
                addQueryParameter("file", encryptedData[0])
                addQueryParameter("expiry", encryptedData[1])
                addQueryParameter("mac", signature)
            }.build().toString()

            Video(url, "(${formatBytes(vid.size.toLongOrNull() ?: 0L)}) ${vid.name}", url)
        }
    }

    private fun signRequest(driveId: String): Pair<String, String> {
        val signReqFunc = jsFile.substringAfter("function signRequest")
            .substringBefore("return")

        val keyStr = signReqFunc.substringAfter("encode('").substringBefore("'").toByteArray()
        val hmacKey = SecretKeySpec(keyStr, "HmacSHA256")
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(hmacKey)

        val expires = System.currentTimeMillis() + 345600000L

        val requestData = "$driveId@$expires".toByteArray()
        val signature = Base64.encodeToString(hmac.doFinal(requestData), Base64.NO_WRAP)
            .replace("+", "-")
        return Pair(signature, expires.toString())
    }

    fun encodeBase64(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP)
    }

    override fun videoListRequest(episode: SEpisode): Request = throw Exception("Not used")

    override fun videoListParse(response: Response): List<Video> = throw Exception("Not used")

    // ============================= Utilities ==============================

    override fun List<Video>.sort(): List<Video> {
        val quality = preferences.getString(PREF_QUALITY_KEY, PREF_QUALITY_DEFAULT)!!

        return this.sortedWith(
            compareBy(
                { it.quality.contains(quality) },
                { Regex("""(\d+)p""").find(it.quality)?.groupValues?.get(1)?.toIntOrNull() ?: 0 },
            ),
        ).reversed()
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1_000_000_000 -> "%.2f GB".format(bytes / 1_000_000_000.0)
            bytes >= 1_000_000 -> "%.2f MB".format(bytes / 1_000_000.0)
            bytes >= 1_000 -> "%.2f KB".format(bytes / 1_000.0)
            bytes > 1 -> "$bytes bytes"
            bytes == 1L -> "$bytes byte"
            else -> ""
        }
    }

    private fun parseDate(dateStr: String): Long {
        return runCatching { DATE_FORMATTER.parse(dateStr)?.time }
            .getOrNull() ?: 0L
    }

    private fun getPath(funcName: String): String {
        return jsFile.substringAfter("function $funcName")
            .substringAfter("apiUrl")
            .substringAfter("'")
            .substringBefore("'")
    }

    private fun LinkData.toJsonString(): String {
        return json.encodeToString(this)
    }

    private inline fun <reified T> Response.parseAs(transform: (String) -> String = { it }): T {
        val responseBody = use { transform(it.body.string()) }
        return json.decodeFromString(responseBody)
    }

    companion object {
        private val DATE_FORMATTER by lazy {
            SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH)
        }

        private val CACHE_CONTROL = CacheControl.Builder().noStore().build()

        private const val PREF_QUALITY_KEY = "preferred_quality"
        private val PREF_QUALITY_ENTRY_VALUES = arrayOf("1080", "720", "480", "360")
        private val PREF_QUALITY_ENTRIES = PREF_QUALITY_ENTRY_VALUES.map { "${it}p" }.toTypedArray()
        private const val PREF_QUALITY_DEFAULT = "1080"
    }

    // ============================== Settings ==============================

    override fun setupPreferenceScreen(screen: PreferenceScreen) {
        ListPreference(screen.context).apply {
            key = PREF_QUALITY_KEY
            title = "Preferred quality"
            entries = PREF_QUALITY_ENTRIES
            entryValues = PREF_QUALITY_ENTRY_VALUES
            setDefaultValue(PREF_QUALITY_DEFAULT)
            summary = "%s"

            setOnPreferenceChangeListener { _, newValue ->
                val selected = newValue as String
                val index = findIndexOfValue(selected)
                val entry = entryValues[index] as String
                preferences.edit().putString(key, entry).commit()
            }
        }.also(screen::addPreference)
    }
}
