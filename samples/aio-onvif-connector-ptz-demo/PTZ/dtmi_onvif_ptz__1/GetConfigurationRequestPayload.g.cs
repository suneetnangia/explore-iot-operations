/* Code generated by Azure.Iot.Operations.ProtocolCompiler; DO NOT EDIT. */

#nullable enable

namespace PTZ.dtmi_onvif_ptz__1
{
    using System;
    using System.Collections.Generic;
    using System.Text.Json.Serialization;
    using PTZ;

    public class GetConfigurationRequestPayload : IJsonOnDeserialized, IJsonOnSerializing
    {
        /// <summary>
        /// The Command request argument.
        /// </summary>
        [JsonPropertyName("GetConfiguration")]
        [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
        [JsonRequired]
        public Object_Onvif_Ptz_GetConfiguration__1 GetConfiguration { get; set; } = default!;

        void IJsonOnDeserialized.OnDeserialized()
        {
            if (GetConfiguration is null)
            {
                throw new ArgumentNullException("GetConfiguration field cannot be null");
            }
        }

        void IJsonOnSerializing.OnSerializing()
        {
            if (GetConfiguration is null)
            {
                throw new ArgumentNullException("GetConfiguration field cannot be null");
            }
        }
    }
}
