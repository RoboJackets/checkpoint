module Main exposing (..)

import Browser
import Browser.Dom exposing (..)
import Browser.Navigation as Nav
import Dict exposing (..)
import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing (..)
import Http exposing (..)
import Json.Decode exposing (..)
import Json.Decode.Pipeline
import Json.Encode
import Svg exposing (Svg, path, svg)
import Svg.Attributes exposing (d)
import Task
import Time exposing (..)
import Url
import Url.Builder
import Url.Parser exposing ((</>), (<?>))
import Url.Parser.Query



-- ICONS


shieldSearchIcon : String -> Svg msg
shieldSearchIcon size =
    svg [ Svg.Attributes.width size, Svg.Attributes.height size, Svg.Attributes.viewBox "0 0 24 24", Svg.Attributes.fill "currentColor", Svg.Attributes.style "top: -0.125em; position: relative;" ] [ path [ d "M12,9A3,3 0 0,1 15,12A3,3 0 0,1 12,15A3,3 0 0,1 9,12A3,3 0 0,1 12,9M17.86,19.31C16.23,21.22 14.28,22.45 12,23C9.44,22.39 7.3,20.93 5.58,18.63C3.86,16.34 3,13.8 3,11V5L12,1L21,5V11C21,13.39 20.36,15.61 19.08,17.67L16.17,14.76C16.69,13.97 17,13 17,12A5,5 0 0,0 12,7A5,5 0 0,0 7,12A5,5 0 0,0 12,17C13,17 13.97,16.69 14.76,16.17L17.86,19.31Z" ] [] ]


magnifyIcon : Svg msg
magnifyIcon =
    svg [ Svg.Attributes.width "16", Svg.Attributes.height "16", Svg.Attributes.viewBox "2 2 20 20", Svg.Attributes.fill "currentColor", Svg.Attributes.style "top: -0.125em; position: relative;" ] [ path [ d "M9.5,3A6.5,6.5 0 0,1 16,9.5C16,11.11 15.41,12.59 14.44,13.73L14.71,14H15.5L20.5,19L19,20.5L14,15.5V14.71L13.73,14.44C12.59,15.41 11.11,16 9.5,16A6.5,6.5 0 0,1 3,9.5A6.5,6.5 0 0,1 9.5,3M9.5,5C7,5 5,7 5,9.5C5,12 7,14 9.5,14C12,14 14,12 14,9.5C14,7 12,5 9.5,5Z" ] [] ]


spinner : Html msg
spinner =
    div [ class "spinner-border", class "spinner-border-sm", style "display" "inline-block" ] []



-- STRINGS


noBreakSpace : String
noBreakSpace =
    String.fromChar '\u{00A0}'



-- TYPES


type alias SearchResult =
    { directoryId : String
    , givenName : String
    , surname : String
    , title : Maybe String
    , organizationalUnit : Maybe String
    , primaryAffiliation : Maybe String
    , affiliations : List String
    }


type alias SearchResults =
    { exactMatch : Bool
    , results : List SearchResult
    }


type alias WhitepagesEntry =
    { dn : String
    , attributes : Dict String (List String)
    }


type alias GtedAccount =
    { eduPersonPrimaryAffiliation : String
    , eduPersonScopedAffiliation : List String
    , givenName : String
    , gtAccountEntitlement : List String
    , gtCurriculum : List String
    , gtEmployeeHomeDepartmentName : Maybe String
    , gtGTID : String
    , gtPersonDirectoryId : String
    , gtPrimaryGTAccountUsername : String
    , sn : String
    , uid : String
    }


type alias KeycloakAccount =
    { id : String
    , enabled : Bool
    , attributes : Dict String (List String)
    }


type alias Event =
    { actorDisplayName : String
    , actorLink : Maybe String
    , eventDescription : String
    , eventLink : Maybe String
    , eventTimestamp : Time.Posix
    }


type alias SelectedUser =
    { directoryId : String
    , whitepagesEntries : Maybe (Result Http.Error (List WhitepagesEntry))
    , gtedAccounts : Maybe (Result Http.Error (List GtedAccount))
    , keycloakAccount : Maybe (Result Http.Error (Maybe KeycloakAccount))
    , events : Maybe (Result Http.Error (List Event))
    }


type Route
    = SearchBox
    | ViewSearchResults (Maybe String)
    | ViewPerson String


type alias Model =
    { navKey : Nav.Key
    , route : Maybe Route
    , loggedInUsername : String
    , majors : Dict String (Maybe String)
    , searchQuery : String
    , loadingSearchResults : Bool
    , searchResults : Maybe (Result Http.Error SearchResults)
    , selectedUser : Maybe SelectedUser
    , keycloakDeepLinkBaseUrl : String
    , apiaryBaseUrl : String
    , zone : Time.Zone
    , zoneName : Time.ZoneName
    }


type Msg
    = UrlRequest Browser.UrlRequest
    | UrlChanged Url.Url
    | SearchQueryInput String
    | SearchRequestSubmitted
    | SearchResultsReceived (Result Http.Error SearchResults)
    | WhitepagesEntriesReceived (Result Http.Error (List WhitepagesEntry))
    | GtedAccountsReceived (Result Http.Error (List GtedAccount))
    | KeycloakAccountReceived (Result Http.Error (Maybe KeycloakAccount))
    | EventsReceived (Result Http.Error (List Event))
    | SetZone Time.Zone
    | SetZoneName Time.ZoneName
    | NoOpMsg



-- PLUMBING


main : Program Value Model Msg
main =
    Browser.application
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = UrlRequest
        }


init : Value -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init flags url navKey =
    ( buildInitialModel flags url navKey
    , Cmd.batch
        [ case Url.Parser.parse urlParser url of
            Just SearchBox ->
                Task.attempt (\_ -> NoOpMsg) (focus "search")

            Just (ViewSearchResults (Just query)) ->
                if String.trim query /= "" then
                    Http.post
                        { url =
                            Url.Builder.absolute
                                [ "search" ]
                                []
                        , body =
                            jsonBody
                                (Json.Encode.object
                                    [ ( "query", Json.Encode.string (String.trim query) )
                                    ]
                                )
                        , expect = expectJson SearchResultsReceived searchResultsResponseDecoder
                        }

                else
                    Cmd.none

            Just (ViewSearchResults Nothing) ->
                Cmd.none

            Just (ViewPerson directoryId) ->
                fetchViewPersonData directoryId

            Nothing ->
                Task.attempt (\_ -> NoOpMsg) (focus "search")
        , Task.perform SetZone Time.here
        , Task.perform SetZoneName Time.getZoneName
        ]
    )


view : Model -> Browser.Document Msg
view model =
    case model.route of
        Just SearchBox ->
            viewSearchBox model

        Nothing ->
            viewSearchBox model

        Just (ViewSearchResults _) ->
            viewSearchResults model

        Just (ViewPerson _) ->
            viewPerson model


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        SearchQueryInput str ->
            ( { model
                | searchQuery = str
              }
            , Cmd.none
            )

        SearchRequestSubmitted ->
            ( { model
                | loadingSearchResults = True
                , searchResults = Nothing
              }
            , Http.post
                { url =
                    Url.Builder.absolute
                        [ "search" ]
                        []
                , body =
                    jsonBody
                        (Json.Encode.object
                            [ ( "query", Json.Encode.string (String.trim model.searchQuery) )
                            ]
                        )
                , expect = expectJson SearchResultsReceived searchResultsResponseDecoder
                }
            )

        SearchResultsReceived result ->
            ( { model
                | searchResults = Just result
                , loadingSearchResults = False
                , selectedUser =
                    case result of
                        Ok searchResults ->
                            if searchResults.exactMatch && List.length searchResults.results == 1 then
                                Just { directoryId = (Maybe.withDefault { directoryId = "", givenName = "", surname = "", title = Nothing, organizationalUnit = Nothing, primaryAffiliation = Nothing, affiliations = [] } (List.head searchResults.results)).directoryId, whitepagesEntries = Nothing, gtedAccounts = Nothing, keycloakAccount = Nothing, events = Nothing }

                            else
                                Nothing

                        Err _ ->
                            Nothing
              }
            , case result of
                Ok searchResults ->
                    if searchResults.exactMatch && List.length searchResults.results == 1 then
                        Nav.pushUrl model.navKey (urlUnparser (ViewPerson (Maybe.withDefault { directoryId = "", givenName = "", surname = "", title = Nothing, organizationalUnit = Nothing, primaryAffiliation = Nothing, affiliations = [] } (List.head searchResults.results)).directoryId))

                    else
                        Nav.pushUrl model.navKey (urlUnparser (ViewSearchResults (Just (String.trim model.searchQuery))))

                Err _ ->
                    Nav.pushUrl model.navKey (urlUnparser (ViewSearchResults (Just (String.trim model.searchQuery))))
            )

        WhitepagesEntriesReceived result ->
            ( { model
                | selectedUser =
                    case model.selectedUser of
                        Just selectedUser ->
                            Just { selectedUser | whitepagesEntries = Just result }

                        Nothing ->
                            Nothing
              }
            , Cmd.none
            )

        GtedAccountsReceived result ->
            ( { model
                | selectedUser =
                    case model.selectedUser of
                        Just selectedUser ->
                            Just { selectedUser | gtedAccounts = Just result }

                        Nothing ->
                            Nothing
              }
            , Cmd.none
            )

        KeycloakAccountReceived result ->
            ( { model
                | selectedUser =
                    case model.selectedUser of
                        Just selectedUser ->
                            Just { selectedUser | keycloakAccount = Just result }

                        Nothing ->
                            Nothing
              }
            , Cmd.none
            )

        EventsReceived result ->
            ( { model
                | selectedUser =
                    case model.selectedUser of
                        Just selectedUser ->
                            Just { selectedUser | events = Just result }

                        Nothing ->
                            Nothing
              }
            , Cmd.none
            )

        NoOpMsg ->
            ( model, Cmd.none )

        UrlRequest request ->
            case request of
                Browser.Internal url ->
                    ( { model | route = Url.Parser.parse urlParser url }
                    , Nav.pushUrl model.navKey (Url.toString url)
                    )

                Browser.External url ->
                    ( model
                    , Nav.load url
                    )

        UrlChanged url ->
            ( { model
                | route = Url.Parser.parse urlParser url
                , selectedUser =
                    case Url.Parser.parse urlParser url of
                        Just (ViewPerson directoryId) ->
                            Just { directoryId = directoryId, whitepagesEntries = Nothing, gtedAccounts = Nothing, keycloakAccount = Nothing, events = Nothing }

                        _ ->
                            Nothing
              }
            , case Url.Parser.parse urlParser url of
                Just SearchBox ->
                    Task.attempt (\_ -> NoOpMsg) (focus "search")

                Just (ViewSearchResults _) ->
                    Cmd.none

                Just (ViewPerson directoryId) ->
                    fetchViewPersonData directoryId

                Nothing ->
                    Cmd.none
            )

        SetZone zone ->
            ( { model
                | zone = zone
              }
            , Cmd.none
            )

        SetZoneName zoneName ->
            ( { model
                | zoneName = zoneName
              }
            , Cmd.none
            )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none



-- HELPERS


urlParser : Url.Parser.Parser (Route -> a) a
urlParser =
    Url.Parser.oneOf
        [ Url.Parser.map SearchBox <| Url.Parser.top
        , Url.Parser.map ViewSearchResults <| Url.Parser.s "search" <?> Url.Parser.Query.string "query"
        , Url.Parser.map ViewPerson <| Url.Parser.s "view" </> Url.Parser.string
        ]


urlUnparser : Route -> String
urlUnparser route =
    case route of
        SearchBox ->
            Url.Builder.absolute [] []

        ViewSearchResults (Just searchQuery) ->
            if String.trim searchQuery == "" then
                Url.Builder.absolute [ "search" ] []

            else
                Url.Builder.absolute [ "search" ] [ Url.Builder.string "query" (String.trim searchQuery) ]

        ViewSearchResults Nothing ->
            Url.Builder.absolute [ "search" ] []

        ViewPerson directoryId ->
            Url.Builder.absolute [ "view", directoryId ] []


buildInitialModel : Value -> Url.Url -> Nav.Key -> Model
buildInitialModel serverData url navKey =
    Model
        navKey
        (Url.Parser.parse urlParser url)
        (String.trim (Result.withDefault "" (decodeValue (at [ "username" ] string) serverData)))
        (Result.withDefault Dict.empty (decodeValue (at [ "majors" ] (Json.Decode.dict (nullable string))) serverData))
        (case Url.Parser.parse urlParser url of
            Just (ViewSearchResults query) ->
                Maybe.withDefault "" query

            _ ->
                ""
        )
        (case Url.Parser.parse urlParser url of
            Just (ViewSearchResults (Just searchQuery)) ->
                String.trim searchQuery /= ""

            _ ->
                False
        )
        Nothing
        (case Url.Parser.parse urlParser url of
            Just (ViewPerson directoryId) ->
                Just
                    (SelectedUser
                        directoryId
                        Nothing
                        Nothing
                        Nothing
                        Nothing
                    )

            _ ->
                Nothing
        )
        (String.trim (Result.withDefault "" (decodeValue (at [ "keycloakDeepLinkBaseUrl" ] string) serverData)))
        (String.trim (Result.withDefault "" (decodeValue (at [ "apiaryBaseUrl" ] string) serverData)))
        Time.utc
        (Time.Name "UTC")


searchResultsResponseDecoder : Decoder SearchResults
searchResultsResponseDecoder =
    Json.Decode.map2 SearchResults
        (at [ "exactMatch" ] Json.Decode.bool)
        (at [ "results" ] (Json.Decode.list searchResultDecoder))


searchResultDecoder : Decoder SearchResult
searchResultDecoder =
    Json.Decode.map7 SearchResult
        (at [ "directoryId" ] Json.Decode.string)
        (at [ "givenName" ] Json.Decode.string)
        (at [ "surname" ] Json.Decode.string)
        (maybe (at [ "title" ] Json.Decode.string))
        (maybe (at [ "organizationalUnit" ] Json.Decode.string))
        (maybe (at [ "primaryAffiliation" ] Json.Decode.string))
        (at [ "affiliations" ] (Json.Decode.list string))


whitepagesResponseDecoder : Decoder (List WhitepagesEntry)
whitepagesResponseDecoder =
    Json.Decode.list whitepagesEntryDecoder


whitepagesEntryDecoder : Decoder WhitepagesEntry
whitepagesEntryDecoder =
    Json.Decode.map2 WhitepagesEntry
        (at [ "dn" ] Json.Decode.string)
        (at [ "attributes" ] (Json.Decode.dict (Json.Decode.list string)))


keycloakResponseDecoder : Decoder (Maybe KeycloakAccount)
keycloakResponseDecoder =
    Json.Decode.maybe
        (Json.Decode.map3 KeycloakAccount
            (at [ "id" ] Json.Decode.string)
            (at [ "enabled" ] Json.Decode.bool)
            (at [ "attributes" ] (Json.Decode.dict (Json.Decode.list string)))
        )


eventsResponseDecoder : Decoder (List Event)
eventsResponseDecoder =
    Json.Decode.list eventDecoder


eventTimestampDecoder : Decoder Time.Posix
eventTimestampDecoder =
    Json.Decode.map Time.millisToPosix Json.Decode.int


eventDecoder : Decoder Event
eventDecoder =
    Json.Decode.map5 Event
        (at [ "actorDisplayName" ] Json.Decode.string)
        (maybe (at [ "actorLink" ] Json.Decode.string))
        (at [ "eventDescription" ] Json.Decode.string)
        (maybe (at [ "eventLink" ] Json.Decode.string))
        (at [ "eventTimestamp" ] eventTimestampDecoder)


gtedResponseDecoder : Decoder (List GtedAccount)
gtedResponseDecoder =
    Json.Decode.list gtedAccountDecoder


gtedAccountDecoder : Decoder GtedAccount
gtedAccountDecoder =
    Json.Decode.succeed GtedAccount
        |> Json.Decode.Pipeline.required "eduPersonPrimaryAffiliation" string
        |> Json.Decode.Pipeline.required "eduPersonScopedAffiliation" (Json.Decode.list string)
        |> Json.Decode.Pipeline.required "givenName" string
        |> Json.Decode.Pipeline.required "gtAccountEntitlement" (Json.Decode.list string)
        |> Json.Decode.Pipeline.optional "gtCurriculum" (Json.Decode.list string) []
        |> Json.Decode.Pipeline.optional "gtEmployeeHomeDepartmentName" (nullable string) Nothing
        |> Json.Decode.Pipeline.required "gtGTID" string
        |> Json.Decode.Pipeline.required "gtPersonDirectoryId" string
        |> Json.Decode.Pipeline.required "gtPrimaryGTAccountUsername" string
        |> Json.Decode.Pipeline.required "sn" string
        |> Json.Decode.Pipeline.required "uid" string


viewSearchBox : Model -> Browser.Document Msg
viewSearchBox model =
    { title = "Checkpoint"
    , body =
        [ div [ style "text-align" "right", style "margin" "1em", class "text-secondary" ]
            [ text model.loggedInUsername
            ]
        , div [ style "align-items" "center", style "justify-content" "center", style "display" "flex", style "text-align" "center", style "height" "90vh", style "flex-direction" "column" ]
            [ div [ class "container", style "height" "8rem", style "max-width" "36rem" ]
                [ div []
                    [ h1 []
                        [ shieldSearchIcon "1.3em"
                        , text " Checkpoint"
                        ]
                    ]
                , div [ class "container", style "max-width" "36rem" ]
                    [ Html.form
                        [ class "row"
                        , class "mt-5"
                        , method "POST"
                        , action "/"
                        , novalidate False
                        , onSubmit SearchRequestSubmitted
                        ]
                        [ div [ class "input-group" ]
                            [ input
                                [ id "search"
                                , name "search"
                                , type_ "search"
                                , class "form-control"
                                , minlength 2
                                , Html.Attributes.required True
                                , readonly model.loadingSearchResults
                                , placeholder "Search for anyone"
                                , onInput SearchQueryInput
                                , Html.Attributes.value model.searchQuery
                                ]
                                []
                            , button
                                [ classList
                                    [ ( "btn", True )
                                    , ( "btn-primary", True )
                                    , ( "rounded-end", True )
                                    ]
                                , type_ "submit"
                                , id "submit_search"
                                , disabled model.loadingSearchResults
                                ]
                                [ if model.loadingSearchResults then
                                    spinner

                                  else
                                    magnifyIcon
                                , text
                                    (noBreakSpace
                                        ++ noBreakSpace
                                        ++ "Search"
                                    )
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ]
    }


affiliationToBadge : String -> Html msg
affiliationToBadge affiliation =
    span [ class "badge", class "rounded-pill", class "text-bg-secondary", class "me-1" ] [ text affiliation ]


removePrimaryAffiliation : Maybe String -> String -> Bool
removePrimaryAffiliation primaryAffiliation thisAffiliation =
    case primaryAffiliation of
        Just anAffiliation ->
            anAffiliation /= thisAffiliation

        Nothing ->
            True


searchResultToHtml : Dict String (Maybe String) -> SearchResult -> Html msg
searchResultToHtml majors result =
    div [ class "mb-4" ]
        ([ h4 [ class "mb-1" ] [ a [ href (urlUnparser (ViewPerson result.directoryId)) ] [ text (result.givenName ++ " " ++ result.surname) ] ]
         , div [ class "mb-1" ] [ text (Maybe.withDefault "" result.title ++ " • " ++ Maybe.withDefault "" (Maybe.map (lookupOrganizationalUnit majors) result.organizationalUnit)) ]
         , span [ class "badge", class "rounded-pill", class "text-bg-primary", class "me-1" ] [ text (Maybe.withDefault "" result.primaryAffiliation) ]
         ]
            ++ List.map affiliationToBadge (List.filter (removePrimaryAffiliation result.primaryAffiliation) result.affiliations)
        )


searchResultPlaceholder : Html msg
searchResultPlaceholder =
    div [ class "mb-4" ]
        [ h4 [ class "mb-1", class "placeholder-wave" ] [ span [ class "placeholder", class "col-2", class "me-1" ] [], span [ class "placeholder", class "col-3" ] [] ]
        , div [ class "mb-1", class "placeholder-wave" ] [ span [ class "placeholder", class "col-1", class "me-1" ] [], span [ class "placeholder", class "col-2" ] [] ]
        , span [ class "rounded-pill", class "me-1", class "placeholder", class "placeholder-wave", class "col-1" ] []
        , span [ class "rounded-pill", class "me-1", class "placeholder", class "placeholder-wave", class "col-1" ] []
        , span [ class "rounded-pill", class "me-1", class "placeholder", class "placeholder-wave", class "col-1" ] []
        , span [ class "rounded-pill", class "me-1", class "placeholder", class "placeholder-wave", class "col-1" ] []
        ]


renderNavbar : Model -> Html Msg
renderNavbar model =
    nav [ class "navbar", class "navbar-expand-md", class "fixed-top", style "backdrop-filter" "blur(6px)", style "background-color" "rgba(255, 255, 255, .3)" ]
        [ div [ class "container-fluid", style "max-width" "64rem", class "justify-content-start" ]
            [ a [ class "navbar-brand", href "/" ]
                [ shieldSearchIcon "1.3em"
                , text " Checkpoint"
                ]
            , Html.form [ onSubmit SearchRequestSubmitted, class "flex-grow-1", class "me-3", style "max-width" "36rem" ]
                [ div [ class "input-group" ]
                    [ input
                        [ id "search"
                        , name "search"
                        , type_ "search"
                        , class "form-control"
                        , minlength 2
                        , Html.Attributes.required True
                        , readonly model.loadingSearchResults
                        , placeholder "Search for anyone"
                        , onInput SearchQueryInput
                        , Html.Attributes.value model.searchQuery
                        , style "backdrop-filter" "blur(4px)"
                        , style "background-color" "rgba(255, 255, 255, 0.2)"
                        ]
                        []
                    , button
                        [ classList
                            [ ( "btn", True )
                            , ( "btn-primary", True )
                            , ( "rounded-end", True )
                            ]
                        , type_ "submit"
                        , id "submit_search"
                        , disabled model.loadingSearchResults
                        ]
                        [ if model.loadingSearchResults then
                            spinner

                          else
                            magnifyIcon
                        , text
                            (noBreakSpace
                                ++ noBreakSpace
                                ++ "Search"
                            )
                        ]
                    ]
                ]
            , div [ class "text-secondary", class "ms-auto", class "d-none", class "d-md-block" ]
                [ text model.loggedInUsername
                ]
            ]
        ]


viewSearchResults : Model -> Browser.Document Msg
viewSearchResults model =
    { title =
        case model.route of
            Just (ViewSearchResults (Just searchQuery)) ->
                if String.trim searchQuery /= "" then
                    String.trim searchQuery ++ " — Checkpoint"

                else
                    "Checkpoint"

            _ ->
                "Checkpoint"
    , body =
        [ renderNavbar model
        , div [ class "container", style "max-width" "64rem", style "margin-top" "5rem" ]
            (case model.searchResults of
                Just result ->
                    case result of
                        Ok searchResults ->
                            if List.isEmpty searchResults.results then
                                if searchResults.exactMatch then
                                    [ div [ style "text-align" "center", class "text-secondary", style "margin-top" "8rem" ]
                                        [ p [] [ text "No results" ]
                                        , p [] [ a [ href (model.apiaryBaseUrl ++ "/nova/resources/users?users_search=" ++ Url.percentEncode (String.trim model.searchQuery)), target "_blank" ] [ text "Try searching in Apiary?" ] ]
                                        ]
                                    ]

                                else
                                    [ div [ style "text-align" "center", class "text-secondary", style "margin-top" "8rem" ] [ text "No results" ]
                                    ]

                            else
                                List.map (searchResultToHtml model.majors) searchResults.results

                        Err err ->
                            [ div [ class "alert", class "alert-danger" ]
                                [ text
                                    ((case err of
                                        BadUrl errorMessage ->
                                            errorMessage

                                        Timeout ->
                                            "There was a timeout while loading search results."

                                        NetworkError ->
                                            "There was a network error while loading search results."

                                        BadStatus statusCode ->
                                            "The server returned status code " ++ String.fromInt statusCode ++ "."

                                        BadBody errorMessage ->
                                            "There was an error parsing the response from the server: " ++ errorMessage ++ "."
                                     )
                                        ++ " Reload the page to try again."
                                    )
                                ]
                            ]

                Nothing ->
                    if model.loadingSearchResults then
                        [ searchResultPlaceholder
                        , searchResultPlaceholder
                        , searchResultPlaceholder
                        ]

                    else
                        []
            )
        ]
    }


filterMatchingDirectoryId : String -> SearchResult -> Bool
filterMatchingDirectoryId selectedDirectoryId thisResult =
    selectedDirectoryId == thisResult.directoryId


getSelectedPersonGivenName : Model -> Maybe String
getSelectedPersonGivenName model =
    case model.selectedUser of
        Just selectedUser ->
            case model.searchResults of
                Just result ->
                    case result of
                        Ok searchResults ->
                            case List.head (List.filter (filterMatchingDirectoryId selectedUser.directoryId) searchResults.results) of
                                Just matchedResult ->
                                    Just matchedResult.givenName

                                Nothing ->
                                    Nothing

                        Err _ ->
                            Nothing

                Nothing ->
                    case selectedUser.gtedAccounts of
                        Just result ->
                            case result of
                                Ok accounts ->
                                    case List.head accounts of
                                        Just account ->
                                            Just account.givenName

                                        Nothing ->
                                            Nothing

                                Err _ ->
                                    Nothing

                        Nothing ->
                            Nothing

        Nothing ->
            Nothing


getSelectedPersonSurname : Model -> Maybe String
getSelectedPersonSurname model =
    case model.selectedUser of
        Just selectedUser ->
            case model.searchResults of
                Just result ->
                    case result of
                        Ok searchResults ->
                            case List.head (List.filter (filterMatchingDirectoryId selectedUser.directoryId) searchResults.results) of
                                Just matchedResult ->
                                    Just matchedResult.surname

                                Nothing ->
                                    Nothing

                        Err _ ->
                            Nothing

                Nothing ->
                    case selectedUser.gtedAccounts of
                        Just result ->
                            case result of
                                Ok accounts ->
                                    case List.head accounts of
                                        Just account ->
                                            Just account.sn

                                        Nothing ->
                                            Nothing

                                Err _ ->
                                    Nothing

                        Nothing ->
                            Nothing

        Nothing ->
            Nothing


ignoreSecondaryTitle : String -> Bool
ignoreSecondaryTitle title =
    not (String.contains "student assistant" (String.toLower title))
        && not (String.contains "research assistant" (String.toLower title))
        && not (String.contains "graduate assistant" (String.toLower title))
        && not (String.contains "instructional associate" (String.toLower title))
        && not (String.contains "research technologist" (String.toLower title))


ignoreSecondaryWhitepagesEntry : WhitepagesEntry -> Bool
ignoreSecondaryWhitepagesEntry entry =
    case Dict.get "title" entry.attributes of
        Just attributeList ->
            List.all ignoreSecondaryTitle attributeList

        Nothing ->
            True


getSelectedPersonTitle : Model -> Maybe String
getSelectedPersonTitle model =
    case model.selectedUser of
        Just selectedUser ->
            case model.searchResults of
                Just result ->
                    case result of
                        Ok searchResults ->
                            case List.head (List.filter (filterMatchingDirectoryId selectedUser.directoryId) searchResults.results) of
                                Just matchedResult ->
                                    matchedResult.title

                                Nothing ->
                                    Nothing

                        Err _ ->
                            Nothing

                Nothing ->
                    case selectedUser.whitepagesEntries of
                        Just result ->
                            case result of
                                Ok entries ->
                                    if List.isEmpty entries then
                                        Nothing

                                    else if List.length entries == 1 then
                                        case List.head entries of
                                            Just entry ->
                                                case Dict.get "title" entry.attributes of
                                                    Just attributeList ->
                                                        List.head attributeList

                                                    Nothing ->
                                                        Nothing

                                            Nothing ->
                                                Nothing

                                    else
                                        case List.head (List.filter ignoreSecondaryWhitepagesEntry entries) of
                                            Just primaryEntry ->
                                                case Dict.get "title" primaryEntry.attributes of
                                                    Just attributeList ->
                                                        List.head attributeList

                                                    Nothing ->
                                                        Nothing

                                            Nothing ->
                                                Nothing

                                Err _ ->
                                    Nothing

                        Nothing ->
                            Nothing

        Nothing ->
            Nothing


filterSimpleGtCurriculum : String -> Bool
filterSimpleGtCurriculum gtCurriculum =
    List.length (String.split "/" gtCurriculum) == 3


lookupOrganizationalUnit : Dict String (Maybe String) -> String -> String
lookupOrganizationalUnit majors ou =
    case Dict.get ou majors of
        Just (Just displayName) ->
            displayName

        _ ->
            ou


getSelectedPersonOrganizationalUnit : Model -> Maybe String
getSelectedPersonOrganizationalUnit model =
    let
        rawOrganizationalUnit : Maybe String
        rawOrganizationalUnit =
            case model.selectedUser of
                Just selectedUser ->
                    case model.searchResults of
                        Just result ->
                            case result of
                                Ok searchResults ->
                                    case List.head (List.filter (filterMatchingDirectoryId selectedUser.directoryId) searchResults.results) of
                                        Just matchedResult ->
                                            matchedResult.organizationalUnit

                                        Nothing ->
                                            Nothing

                                Err _ ->
                                    Nothing

                        Nothing ->
                            case selectedUser.whitepagesEntries of
                                Just result ->
                                    case result of
                                        Ok entries ->
                                            if List.isEmpty entries then
                                                case selectedUser.gtedAccounts of
                                                    Just gtedResult ->
                                                        case gtedResult of
                                                            Ok accounts ->
                                                                case List.head (List.filter filterSimpleGtCurriculum (Maybe.withDefault { eduPersonPrimaryAffiliation = "", eduPersonScopedAffiliation = [], givenName = "", gtAccountEntitlement = [], gtCurriculum = [], gtEmployeeHomeDepartmentName = Nothing, gtGTID = "", gtPersonDirectoryId = "", gtPrimaryGTAccountUsername = "", sn = "", uid = "" } (List.head accounts)).gtCurriculum) of
                                                                    Just curriculum ->
                                                                        List.head (List.reverse (String.split "/" curriculum))

                                                                    Nothing ->
                                                                        Nothing

                                                            Err _ ->
                                                                Nothing

                                                    Nothing ->
                                                        Nothing

                                            else if List.length entries == 1 then
                                                case List.head entries of
                                                    Just entry ->
                                                        case Dict.get "ou" entry.attributes of
                                                            Just attributeList ->
                                                                List.head attributeList

                                                            Nothing ->
                                                                Nothing

                                                    Nothing ->
                                                        Nothing

                                            else
                                                case List.head (List.filter ignoreSecondaryWhitepagesEntry entries) of
                                                    Just primaryEntry ->
                                                        case Dict.get "ou" primaryEntry.attributes of
                                                            Just attributeList ->
                                                                List.head attributeList

                                                            Nothing ->
                                                                Nothing

                                                    Nothing ->
                                                        Nothing

                                        Err _ ->
                                            Nothing

                                Nothing ->
                                    Nothing

                Nothing ->
                    Nothing
    in
    Maybe.map (lookupOrganizationalUnit model.majors) rawOrganizationalUnit


fetchViewPersonData : String -> Cmd Msg
fetchViewPersonData directoryId =
    Cmd.batch
        [ Http.get
            { url =
                Url.Builder.absolute
                    [ "view", directoryId, "whitepages" ]
                    []
            , expect = expectJson WhitepagesEntriesReceived whitepagesResponseDecoder
            }
        , Http.get
            { url =
                Url.Builder.absolute
                    [ "view", directoryId, "gted" ]
                    []
            , expect = expectJson GtedAccountsReceived gtedResponseDecoder
            }
        , Http.get
            { url =
                Url.Builder.absolute
                    [ "view", directoryId, "keycloak" ]
                    []
            , expect = expectJson KeycloakAccountReceived keycloakResponseDecoder
            }
        , Http.get
            { url =
                Url.Builder.absolute
                    [ "view", directoryId, "events" ]
                    []
            , expect = expectJson EventsReceived eventsResponseDecoder
            }
        ]


whitepagesEntryToEmployeeTypePill : WhitepagesEntry -> Html Msg
whitepagesEntryToEmployeeTypePill entry =
    span [ class "badge", class "rounded-pill", class "text-bg-primary", class "me-1" ]
        [ text
            (case Dict.get "employeeType" entry.attributes of
                Just attributeList ->
                    case List.head attributeList of
                        Just employeeType ->
                            employeeType

                        Nothing ->
                            ""

                Nothing ->
                    ""
            )
        ]


gtedAccountToPrimaryAffiliationPill : GtedAccount -> Html Msg
gtedAccountToPrimaryAffiliationPill account =
    span [ class "badge", class "rounded-pill", class "text-bg-primary", class "me-1" ] [ text account.eduPersonPrimaryAffiliation ]


viewPerson : Model -> Browser.Document Msg
viewPerson model =
    let
        titleIsLoading : Bool
        titleIsLoading =
            case model.selectedUser of
                Just selectedUser ->
                    case selectedUser.gtedAccounts of
                        Just (Err (BadStatus 404)) ->
                            False

                        _ ->
                            case getSelectedPersonTitle model of
                                Just _ ->
                                    False

                                Nothing ->
                                    case selectedUser.whitepagesEntries of
                                        Just (Ok []) ->
                                            False

                                        _ ->
                                            True

                Nothing ->
                    False

        organizationalUnitIsLoading : Bool
        organizationalUnitIsLoading =
            case model.selectedUser of
                Just selectedUser ->
                    case selectedUser.gtedAccounts of
                        Just (Err (BadStatus 404)) ->
                            False

                        _ ->
                            case getSelectedPersonOrganizationalUnit model of
                                Just _ ->
                                    False

                                Nothing ->
                                    case selectedUser.whitepagesEntries of
                                        Just (Ok []) ->
                                            case selectedUser.gtedAccounts of
                                                Just _ ->
                                                    False

                                                Nothing ->
                                                    True

                                        _ ->
                                            True

                Nothing ->
                    False
    in
    { title =
        if getSelectedPersonGivenName model /= Nothing && getSelectedPersonSurname model /= Nothing then
            Maybe.withDefault "" (getSelectedPersonGivenName model) ++ " " ++ Maybe.withDefault "" (getSelectedPersonSurname model) ++ " — Checkpoint"

        else
            "Checkpoint"
    , body =
        [ renderNavbar model
        , div [ class "container", style "max-width" "64rem", style "margin-top" "5rem" ]
            ((case model.selectedUser of
                Just selectedUser ->
                    case selectedUser.gtedAccounts of
                        Just (Err (BadStatus 404)) ->
                            [ div [ class "alert", class "alert-danger" ]
                                [ text "The provided directory ID was not found in GTED. Check the URL."
                                ]
                            ]

                        Just (Err err) ->
                            [ div [ class "alert", class "alert-danger" ]
                                [ text
                                    ((case err of
                                        BadUrl errorMessage ->
                                            errorMessage

                                        Timeout ->
                                            "There was a timeout while retrieving GTED accounts."

                                        NetworkError ->
                                            "There was a network error while retrieving GTED accounts."

                                        BadStatus statusCode ->
                                            "The server returned status code " ++ String.fromInt statusCode ++ " white retrieving GTED accounts."

                                        BadBody errorMessage ->
                                            "There was an error parsing GTED accounts: " ++ errorMessage ++ "."
                                     )
                                        ++ " Reload the page to try again."
                                    )
                                ]
                            ]

                        _ ->
                            []

                Nothing ->
                    []
             )
                ++ (case model.selectedUser of
                        Just selectedUser ->
                            case selectedUser.whitepagesEntries of
                                Just (Err (BadStatus 404)) ->
                                    []

                                Just (Err err) ->
                                    [ div [ class "alert", class "alert-danger" ]
                                        [ text
                                            ((case err of
                                                BadUrl errorMessage ->
                                                    errorMessage

                                                Timeout ->
                                                    "There was a timeout while retrieving Whitepages entries."

                                                NetworkError ->
                                                    "There was a network error while retrieving Whitepages entries."

                                                BadStatus statusCode ->
                                                    "The server returned status code " ++ String.fromInt statusCode ++ " white retrieving Whitepages entries."

                                                BadBody errorMessage ->
                                                    "There was an error parsing Whitepages entries: " ++ errorMessage ++ "."
                                             )
                                                ++ " Reload the page to try again."
                                            )
                                        ]
                                    ]

                                _ ->
                                    []

                        Nothing ->
                            []
                   )
                ++ (case model.selectedUser of
                        Just selectedUser ->
                            case selectedUser.keycloakAccount of
                                Just (Err (BadStatus 404)) ->
                                    []

                                Just (Err err) ->
                                    [ div [ class "alert", class "alert-danger" ]
                                        [ text
                                            ((case err of
                                                BadUrl errorMessage ->
                                                    errorMessage

                                                Timeout ->
                                                    "There was a timeout while retrieving the Keycloak account."

                                                NetworkError ->
                                                    "There was a network error while retrieving the Keycloak account."

                                                BadStatus statusCode ->
                                                    "The server returned status code " ++ String.fromInt statusCode ++ " white retrieving the Keycloak account."

                                                BadBody errorMessage ->
                                                    "There was an error parsing the Keycloak account: " ++ errorMessage ++ "."
                                             )
                                                ++ " Reload the page to try again."
                                            )
                                        ]
                                    ]

                                _ ->
                                    []

                        Nothing ->
                            []
                   )
                ++ (case model.selectedUser of
                        Just selectedUser ->
                            case selectedUser.events of
                                Just (Err (BadStatus 404)) ->
                                    []

                                Just (Err err) ->
                                    [ div [ class "alert", class "alert-danger" ]
                                        [ text
                                            ((case err of
                                                BadUrl errorMessage ->
                                                    errorMessage

                                                Timeout ->
                                                    "There was a timeout while retrieving events."

                                                NetworkError ->
                                                    "There was a network error while retrieving events."

                                                BadStatus statusCode ->
                                                    "The server returned status code " ++ String.fromInt statusCode ++ " white retrieving events."

                                                BadBody errorMessage ->
                                                    "There was an error parsing events: " ++ errorMessage ++ "."
                                             )
                                                ++ " Reload the page to try again."
                                            )
                                        ]
                                    ]

                                _ ->
                                    []

                        Nothing ->
                            []
                   )
                ++ -- show name
                   (case model.selectedUser of
                        Just selectedUser ->
                            case selectedUser.gtedAccounts of
                                Just (Err _) ->
                                    []

                                _ ->
                                    if getSelectedPersonGivenName model /= Nothing && getSelectedPersonSurname model /= Nothing then
                                        [ h4 [ class "mb-1" ] [ text (Maybe.withDefault "" (getSelectedPersonGivenName model) ++ " " ++ Maybe.withDefault "" (getSelectedPersonSurname model)) ]
                                        ]

                                    else
                                        [ h4 [ class "mb-1", class "placeholder-wave" ] [ span [ class "placeholder", class "col-2", class "me-1" ] [], span [ class "placeholder", class "col-3" ] [] ]
                                        ]

                        Nothing ->
                            []
                   )
                ++ -- show title and/or OU
                   (if titleIsLoading || organizationalUnitIsLoading then
                        [ div [ class "mb-1", class "placeholder-wave" ]
                            ((case getSelectedPersonTitle model of
                                Just title ->
                                    [ text title ]

                                Nothing ->
                                    if titleIsLoading then
                                        [ span [ class "placeholder", class "col-1", class "me-1" ] [] ]

                                    else
                                        []
                             )
                                ++ (case getSelectedPersonOrganizationalUnit model of
                                        Just ou ->
                                            [ text ou ]

                                        Nothing ->
                                            if organizationalUnitIsLoading then
                                                [ span [ class "placeholder", class "col-2" ] [] ]

                                            else
                                                []
                                   )
                            )
                        ]

                    else
                        [ div [ class "mb-1" ]
                            (case getSelectedPersonTitle model of
                                Just title ->
                                    case getSelectedPersonOrganizationalUnit model of
                                        Just ou ->
                                            [ text (title ++ " • " ++ ou) ]

                                        Nothing ->
                                            [ text title ]

                                Nothing ->
                                    case getSelectedPersonOrganizationalUnit model of
                                        Just ou ->
                                            [ text ou ]

                                        Nothing ->
                                            []
                            )
                        ]
                   )
                ++ [ h5 [ class "mt-4", class "mb-3" ] [ text "Apps " ]
                   , p [ class "text-secondary" ] [ text "Nothing here, yet" ]
                   , h5 [ class "mt-4", class "mb-3" ] [ text "Directories " ]
                   , div [ class "row" ]
                        [ div [ class "col-3" ]
                            [ div [ class "card" ]
                                [ div [ class "card-body" ]
                                    ([ h6 [] [ text "Whitepages" ]
                                     , a [ target "_blank", href (Url.Builder.absolute [ "view", (Maybe.withDefault { directoryId = "", whitepagesEntries = Nothing, gtedAccounts = Nothing, keycloakAccount = Nothing, events = Nothing } model.selectedUser).directoryId, "whitepages" ] []), class "position-absolute", style "top" "14px", style "right" "14px" ] [ text "View raw" ]
                                     ]
                                        ++ (case model.selectedUser of
                                                Just selectedUser ->
                                                    case selectedUser.whitepagesEntries of
                                                        Just (Err _) ->
                                                            []

                                                        Just (Ok entries) ->
                                                            case List.length entries of
                                                                0 ->
                                                                    [ div [] [ text "No entries" ] ]

                                                                1 ->
                                                                    [ div [ class "mb-1" ] [ text "1 entry" ] ]

                                                                _ ->
                                                                    [ div [ class "mb-1" ] [ text (String.fromInt (List.length entries) ++ " entries") ] ]

                                                        Nothing ->
                                                            [ div [ class "placeholder-wave", class "mb-1" ] [ span [ class "placeholder", class "col-1" ] [] ] ]

                                                Nothing ->
                                                    []
                                           )
                                        ++ (case model.selectedUser of
                                                Just selectedUser ->
                                                    case selectedUser.whitepagesEntries of
                                                        Just (Err _) ->
                                                            []

                                                        Just (Ok entries) ->
                                                            [ div [] (List.map whitepagesEntryToEmployeeTypePill entries) ]

                                                        Nothing ->
                                                            [ div [ class "placeholder-wave" ] [ span [ class "placeholder", class "rounded-pill", class "col-1" ] [] ] ]

                                                Nothing ->
                                                    []
                                           )
                                    )
                                ]
                            ]
                        , div [ class "col-3" ]
                            [ div [ class "card" ]
                                [ div [ class "card-body" ]
                                    ([ h6 [] [ text "GTED" ]
                                     , a [ target "_blank", href ("https://iat.gatech.edu/prod/person/" ++ (Maybe.withDefault { directoryId = "", whitepagesEntries = Nothing, gtedAccounts = Nothing, keycloakAccount = Nothing, events = Nothing } model.selectedUser).directoryId), class "position-absolute", style "top" "14px", style "right" "14px" ] [ text "View in IAT" ]
                                     , a [ target "_blank", href (Url.Builder.absolute [ "view", (Maybe.withDefault { directoryId = "", whitepagesEntries = Nothing, gtedAccounts = Nothing, keycloakAccount = Nothing, events = Nothing } model.selectedUser).directoryId, "gted" ] []), class "position-absolute", style "top" "36px", style "right" "14px" ] [ text "View raw" ]
                                     ]
                                        ++ (case model.selectedUser of
                                                Just selectedUser ->
                                                    case selectedUser.gtedAccounts of
                                                        Just (Err _) ->
                                                            []

                                                        Just (Ok entries) ->
                                                            case List.length entries of
                                                                0 ->
                                                                    [ div [] [ text "No accounts" ] ]

                                                                1 ->
                                                                    [ div [ class "mb-1" ] [ text "1 account" ] ]

                                                                _ ->
                                                                    [ div [ class "mb-1" ] [ text (String.fromInt (List.length entries) ++ " accounts") ] ]

                                                        Nothing ->
                                                            [ div [ class "placeholder-wave", class "mb-1" ] [ span [ class "placeholder", class "col-1" ] [] ] ]

                                                Nothing ->
                                                    []
                                           )
                                        ++ (case model.selectedUser of
                                                Just selectedUser ->
                                                    case selectedUser.gtedAccounts of
                                                        Just (Err _) ->
                                                            []

                                                        Just (Ok accounts) ->
                                                            [ div []
                                                                (case List.head accounts of
                                                                    Just firstAccount ->
                                                                        [ gtedAccountToPrimaryAffiliationPill firstAccount ]

                                                                    Nothing ->
                                                                        []
                                                                )
                                                            ]

                                                        Nothing ->
                                                            [ div [ class "placeholder-wave" ] [ span [ class "placeholder", class "rounded-pill", class "col-1" ] [] ] ]

                                                Nothing ->
                                                    []
                                           )
                                    )
                                ]
                            ]
                        , div [ class "col-3" ]
                            [ div [ class "card" ]
                                [ div [ class "card-body" ]
                                    ([ h6 [] [ text "Keycloak" ]
                                     , a [ target "_blank", href (model.keycloakDeepLinkBaseUrl ++ getKeycloakUserId model ++ "/settings"), class "position-absolute", style "top" "14px", style "right" "14px" ] [ text "View in Keycloak" ]
                                     , a [ target "_blank", href (Url.Builder.absolute [ "view", (Maybe.withDefault { directoryId = "", whitepagesEntries = Nothing, gtedAccounts = Nothing, keycloakAccount = Nothing, events = Nothing } model.selectedUser).directoryId, "keycloak" ] []), class "position-absolute", style "top" "36px", style "right" "14px" ] [ text "View raw" ]
                                     ]
                                        ++ (case model.selectedUser of
                                                Just selectedUser ->
                                                    case selectedUser.keycloakAccount of
                                                        Just (Err _) ->
                                                            []

                                                        Just (Ok (Just _)) ->
                                                            [ div [ class "mb-1" ] [ text "1 account" ] ]

                                                        Just (Ok Nothing) ->
                                                            [ div [] [ text "No account" ] ]

                                                        Nothing ->
                                                            [ div [ class "placeholder-wave", class "mb-1" ] [ span [ class "placeholder", class "col-1" ] [] ] ]

                                                Nothing ->
                                                    []
                                           )
                                        ++ (case model.selectedUser of
                                                Just selectedUser ->
                                                    case selectedUser.keycloakAccount of
                                                        Just (Err _) ->
                                                            []

                                                        Just (Ok (Just account)) ->
                                                            if account.enabled then
                                                                [ span [ class "badge", class "rounded-pill", class "text-bg-primary", class "me-1" ] [ text "enabled" ] ]

                                                            else
                                                                [ span [ class "badge", class "rounded-pill", class "text-bg-secondary", class "me-1" ] [ text "disabled" ] ]

                                                        Just (Ok Nothing) ->
                                                            []

                                                        Nothing ->
                                                            [ div [ class "placeholder-wave" ] [ span [ class "placeholder", class "rounded-pill", class "col-1" ] [] ] ]

                                                Nothing ->
                                                    []
                                           )
                                    )
                                ]
                            ]
                        ]
                   , h5 [ class "mt-4", class "mb-3" ] [ text "Events " ]
                   , div [ class "row" ]
                        [ table [ class "table" ]
                            [ tbody []
                                (case model.selectedUser of
                                    Just selectedUser ->
                                        case selectedUser.events of
                                            Just (Ok events) ->
                                                List.map (eventToHtmlRow model.zone model.zoneName) (List.sortWith sortByEventTimestamp events)

                                            _ ->
                                                []

                                    _ ->
                                        []
                                )
                            ]
                        ]
                   ]
            )
        ]
    }


getKeycloakUserId : Model -> String
getKeycloakUserId model =
    case model.selectedUser of
        Just selectedUser ->
            case selectedUser.keycloakAccount of
                Just (Ok (Just keycloakAccount)) ->
                    keycloakAccount.id

                _ ->
                    ""

        _ ->
            ""


eventToHtmlRow : Time.Zone -> Time.ZoneName -> Event -> Html msg
eventToHtmlRow zone zoneName event =
    tr
        []
        [ td []
            [ abbr
                [ title
                    (case zoneName of
                        Name name ->
                            name

                        Offset offset ->
                            if offset > 0 then
                                "UTC+" ++ String.fromFloat (toFloat offset / 60)

                            else
                                "UTC" ++ String.fromFloat (toFloat offset / 60)
                    )
                ]
                [ text
                    ((((case toMonth zone event.eventTimestamp of
                            Jan ->
                                "January"

                            Feb ->
                                "February"

                            Mar ->
                                "March"

                            Apr ->
                                "April"

                            May ->
                                "May"

                            Jun ->
                                "June"

                            Jul ->
                                "July"

                            Aug ->
                                "August"

                            Sep ->
                                "September"

                            Oct ->
                                "October"

                            Nov ->
                                "November"

                            Dec ->
                                "December"
                       )
                        ++ " "
                        ++ String.fromInt (toDay zone event.eventTimestamp)
                      )
                        ++ ", "
                        ++ String.fromInt (toYear zone event.eventTimestamp)
                        ++ " "
                        ++ String.padLeft 2 '0' (String.fromInt (toHour zone event.eventTimestamp))
                     )
                        ++ ":"
                        ++ String.padLeft 2 '0' (String.fromInt (toMinute zone event.eventTimestamp))
                    )
                ]
            ]
        , td []
            [ case event.actorLink of
                Just link ->
                    a [ href link, target "_blank" ] [ text event.actorDisplayName ]

                Nothing ->
                    text event.actorDisplayName
            , text " "
            , case event.eventLink of
                Just link ->
                    a [ href link, target "_blank" ] [ text event.eventDescription ]

                Nothing ->
                    text event.eventDescription
            ]
        ]


sortByEventTimestamp : Event -> Event -> Order
sortByEventTimestamp first second =
    compare (Time.posixToMillis second.eventTimestamp) (Time.posixToMillis first.eventTimestamp)
