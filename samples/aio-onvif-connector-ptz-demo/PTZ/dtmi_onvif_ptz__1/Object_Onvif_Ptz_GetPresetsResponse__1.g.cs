/* Code generated by Azure.Iot.Operations.ProtocolCompiler; DO NOT EDIT. */

#nullable enable

namespace PTZ.dtmi_onvif_ptz__1
{
    using System;
    using System.Collections.Generic;
    using System.Text.Json.Serialization;
    using PTZ;

    public class Object_Onvif_Ptz_GetPresetsResponse__1
    {
        /// <summary>
        /// A list of presets which are available for the requested MediaProfile.
        /// </summary>
        [JsonPropertyName("Presets")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
        public List<Object_Onvif_Ptz_PTZPreset__1>? Presets { get; set; } = default;

    }
}
